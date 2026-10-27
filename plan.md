# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

**Scope correction — 2026-10-05:** remove the experimental FUSE-backed guarded
source backend and its product integration. Protected folders remain ordinary
native filesystem directories. FUSE completion, guarded Git integration, and
the guarded recapture bug are canceled work; the removal and existing-state
transition replace them. The runtime and dependency are now removed; verified
historical export and the complete upgrade policy remain open. Historical guarded
implementation reports below remain evidence only and do not authorize continued
development. The current removal
contract is in section 4; the remaining non-FUSE corrections and release gates
are in section 8 and `TODO.md`. Native Windows/macOS, metadata, watchers,
application-consistent capture, and the Git byte-preservation requirements
remain in scope.

## 1. Direction and first decisions

- Continue the layered Rust workspace; transplant small proven utilities rather
  than extending BarterBackup's whole-blob core. The current product has two binaries:
  `mutualbackupd` is the sole owner of the live node, databases, peer network,
  and background jobs; `mutualbackup` is a thin local control and offline
  bootstrap CLI. Milestone 6 adds a separate Git-compatible local command
  binary over that same daemon and a versioned source-backend interface; it
  does not create a second live writer or change what guild peers see. A
  bootstrap, DHT, or relay role is a daemon configuration, not another program.
- The implemented first usable prototype baseline is Linux and
  **reflink-only**. Probe the complete COW lifecycle when a root is added and
  reject the root if reflinks are not safe there. Never silently fall back to
  an eager full copy. Remove the experimental FUSE-backed guarded path; do not
  replace it with hard-link freezing or another interception layer. Future
  Windows and macOS backends must use qualified native capture facilities.
- Build the Milestone 6 Git-compatible frontend on native immutable source
  anchors, not a second persistent Git payload store. Reuse a maintained Git
  implementation for object IDs, object formats, refs, index, and pack/protocol
  handling, with a custom object-store adapter where needed; do not reimplement
  SHA-1 or Git serialization from scratch. Git commits, branches, and worktrees
  are owner-local history represented in ordinary protected user data and
  metadata. Guild protocol authority remains the signed MutualBackup revision
  and checkpoint, and peers need no Git awareness. Present the supported basic
  commands through a Git-style local CLI; its native repository is
  `.mutualbackup`, while ordinary Git communicates through object/pack exchange
  rather than opening that directory as `.git`.
  This Git pivot is an addition to the original roadmap: implement it through
  the versioned source-backend boundary alongside the outstanding native
  platform, metadata, watcher, and application-capture work. Milestone 6 must
  deliver both sets of requirements; Milestone 7 freezes their compatibility
  together. Git compatibility must not add a second permanent payload copy
  inside our repository or require Git-specific behavior from other guild members.
- The Git-compatible frontend preserves tracked file bytes exactly. No command
  automatically fixes line endings or applies another content conversion, even
  when the host's Git configuration enables one. This is a requirement of the
  adopted Git pivot: implement it at the versioned source-backend boundary,
  verify it in every Milestone 6 Git slice, and freeze it in Milestone 7 along
  with the outstanding original requirements. Git's `text`/`eol` handling
  can normalize line endings on its own; a configured `filter.<name>.clean`
  command is a separate, arbitrary transformation. Disable both directions of
  both mechanisms rather than assuming that disabling CRLF normalization also
  disables custom filters. Do not invoke configured `textconv`/external diff or
  merge drivers implicitly: display and merge must use the raw tracked bytes,
  and only an explicit user edit or the built-in merge result may create new
  file content. This includes Git LFS filters: an LFS pointer is
  tracked and restored as its literal bytes, with no automatic LFS transfer or
  pointer substitution by our binary. A `.gitattributes` file is itself tracked
  byte-for-byte, but its conversion rules do not transform other files in this
  frontend. This is the repository's fixed behavior, not a Git configuration
  default that a user or installation can override.
  Do not offer a compatibility flag, `--renormalize` equivalent, or per-command
  override that enables such conversion in our binary. Existing Git attributes
  and configuration that request conversion are inert for file content in our
  binary; their presence must not prevent raw-byte operations. This policy
  covers local staging, history, checkout, merge, and interoperability with
  ordinary Git. A later change to attributes or configuration must not rewrite
  a staged or committed blob; only an explicit stage of changed file bytes may
  change its blob ID.
  Git-compatible object IDs describe the bytes actually retained in native
  anchors. Treat Git's automatic conversion settings as disabled in our binary,
  including when opening an existing repository or importing a commit. `add`
  hashes the immutable captured bytes as a raw Git blob, so its object ID must
  match `git hash-object --no-filters` on those bytes. Checkout writes the
  stored blob bytes unchanged; no clean/smudge step is part of either operation.
  This is an intentional compatibility limit: a stock Git peer may present a
  converted worktree, but our repository stores and checks out the exchanged
  Git blob bytes unchanged. Document that difference in the Git-facing CLI.
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
  Historical format-1 coding Adds predate transcript-bound authority. If no
  quorum certificate was issued while trustworthy original evidence remained,
  automatic seed-only recovery of that legacy history fails closed and needs
  trusted assisted recovery. New format-2 Adds retain the permanent invariant.
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

### Implemented baseline — efficient and flexible guild protocol beta

Milestones 0 through 4 have passed. The source-only review through `a6b5d7d`
reopened Milestone 5 for negative verifier evidence losing retry ownership
(M5-119), format-2 renewal competing with a format-3 retry (M5-120), and
offline removed-holder cleanup being reported complete without deletion
(M5-121). Those paths were corrected and the complete local M5-122 gate passed
on exact committed source `4880c28fbfce9a1654f970eb11e71d020e938b37`.
A later source-only review found M5-123 through M5-126 in initial negative
attempt replanning, cross-version renewal and removed-holder discovery.
Those paths were corrected in `9cfa4b5`, `dd942a6`, and `e09a13f`.
The complete local M5-127 gate passed on exact code source `e09a13f`.
A further source-only review of that same code found M5-128 through M5-130:
full-width retired activation can terminate the daemon and strand coverage,
replacement parity can choose an unusable holder, and initial negative coding
evidence can relaunch with the same faulty coordinator. At that review,
Milestone 5 reopened and Milestone 6 waited for M5-131.
The follow-up commits through `ae081a3` add durable post-forget replanning,
capacity-aware parity rotation across retries and expiry, historical
invalid-coder exclusion, and a fresh holder-abort check after Forget.
Committed regressions cover full-width three- and five-domain backup commit
and repeated reopen, plus full and offline first-spare replacement through
coverage and reopen. M5-128 through M5-130 are corrected at source level;
the complete local M5-131 gate passed on exact code source `39a99e7` after
restart/cleanup regressions were aligned with durable handoff. A later
source-only review of the unchanged code found that early holder abort can
leave retired READY parity after Forget (M5-132), and the required
three-member negative-result production/reopen regression is absent (M5-133).
Those corrections and the complete local M5-134 gate passed on exact code
source `a7da0ce`. A later source-only review found that post-Forget cleanup
can delete READY information reused by a verified successor (M5-135), and
ordinary lifecycle Forget can leave completed-group parity without cleanup
ownership (M5-136). M5-135/M5-136/M5-138 were corrected in `9da97eb`, and
the M5-137 local gate passed on `666697a`. A source-only review of `0000d9d`
found M5-139 through M5-142 in same-ID volume receipts, historical Add replay,
pending information retention, and partial repair cleanup. The corrections
are implemented in `123d5af`, `3419415`, `366e9e5`, and `7392e6d`. The
complete local M5-143 gate passed on exact committed code source
`8f60298a74b74fbef8b92b4eb6a00a92385e7a37`, closing Milestone 5 at that
point. A source-only review of `6606cc1` found M5-144 through M5-148:
variable-profile shards are stranded by volume drain; cold recovery and legacy
Forget can each lose historical Add evidence; a certified Add does not bind
its exact verifier attempt against a wrong but replay-valid peer response; and
stale abort leaves virtual-zero-only activation pins. M5-144 now refuses final
retirement while variable-profile objects or reservations remain, preserving
their receipt and readable source until cleanup. M5-146 now atomically
backfills the original Add binding at Forget, including on upgraded stores.
M5-145 now fetches and preserves event-bound evidence for every historical
Add during seed recovery, so a recovered node can serve a lagging member.
M5-148 is corrected: activation checks local assignment before a pin write,
zero-only roles make no pin, and GC retires legacy nonphysical pins. M5-147
now certifies the exact canonical verifier transcript in a new, appended
format-2 Add variant; historical format-1 Add bytes stay decodable. A final
source audit found that those old Adds still accept unbound evidence from a
peer (M5-150). The chosen policy closes M5-150/M5-151 at source level:
ordinary event-tail catch-up rejects format-1 Adds; cold recovery requires an
existing quorum certificate for each such Add and never reattests on demand.
Background migration issues and retains certificates while original signers
are present. A history that lost its original evidence before certification
fails closed and needs trusted assisted recovery. On exact committed source
`04c6d7a`, formatting, strict workspace Clippy, locked all-target workspace
tests and Docker safety passed. Fresh disposable Btrfs acceptance passed all
cases before the five-daemon smoke test, but its first isolated-topology backup
timed out after 5,400 seconds without committing (M5-152). Independent
resource cleanup passed. Two fresh smoke-only runs subsequently passed both
topology backups but did not reproduce the timeout after the preceding Btrfs
matrix. A later all-target workspace rerun exposed a separate three-domain
activation fixture reopen race after 302 passing `mb-node` tests; M5-153 now
waits for the already-running blocking worker to release the directory.
The complete M5-149 gate then passed on exact committed source `0c39244`,
including all 24 provisioned invocations and independent cleanup. M5-152
subsequently explained the earlier 5,400-second topology timeout. The
five-daemon fixture now checks the coordinator-to-fallback
connection before its first topology backup. A fresh diagnostic run passed
that precondition but stalled with verified activations pending and all five
members holding the same signed Add proposal. A debugger sample found repeated
full event-history replay under the node mutex during activation selection,
starving other workers. The authority path now caches verified membership
snapshots until durable guild state changes, and rebuilds on reopen. Focused,
strict workspace and all-target workspace checks pass. A fresh provisioned
five-daemon smoke run on `e44a220` passed both isolated backups, seed/DHT
recovery and independent cleanup in 1,206.63 seconds. The final gate on
committed source `53ec2ec` passed formatting, strict workspace Clippy, the
locked all-target workspace suite, Docker safety, all 24 fresh provisioned
cases (including the five-daemon test in 1,201.82 seconds), and independent
resource cleanup. Milestone 5 is closed; Milestone 6 may proceed.
M5-114's complete local workspace and fresh provisioned gate remain passing
historical evidence for exact source `720920d`, with independently verified
cleanup. Renewal ownership (M5-118), acknowledged retry recovery and
confirmed cleanup completion (M5-116/M5-117) distinguish delegation
acknowledgement from terminal cleanup and retain accepted child ownership.
M5-113 now transfers packed input intent atomically and resumes successor
uploads before delegation; its production partial-upload/offline/reopen,
checkpoint, capacity and cache/GC regressions pass locally.
M5-111/M5-112/M5-115 now arbitrate cleanup at the delegator, yield expired
launches to durable submission owners, and finish retired historical
submissions without blocking later stale cleanup. Focused regressions, strict
locked all-target workspace Clippy/tests, formatting, Docker lab safety and
all 23 fresh Btrfs/network acceptance invocations passed locally on that
earlier source. Earlier source-only review records remain historical.
The M5-113 ownership audit found M5-116's unreachable acknowledged-successor
recovery; the correction now gives retained input intent a reachable recovery
owner. M5-117 requires confirmed cleanup rather than treating a retirement
fence as completion. Both paths passed the final M5-114 gate.

The previous complete final M5-104 local gate on
2026-09-26 passed against `f8e47d34d62a073db6953260571441525dc5e2ac`, including
strict locked workspace Clippy, all-target workspace tests, formatting, Docker
lab safety and all 23 fresh disposable Btrfs/network acceptance invocations.
Cleanup was independently verified. Those outcomes remain historical evidence
for their exact source; the passing regressions do not cover the newly found
interleavings and packed-only retry inputs. The following paragraphs retain
the prior closure/review history.

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
Those source corrections are implemented, and the complete local M5-45
correction gate passed on 2026-09-19. Follow-up source-only review of
`56bb57d..f7d0503` on 2026-09-20 found M5-46 through M5-57, so Milestone 5 was
reopened. Those corrections are implemented, but source-only review of
`f7d0503..81ec33b` on 2026-09-21 found M5-58 through M5-66. M5-58 through M5-66
are corrected. The complete local workspace and provisioned closure gate passed
on 2026-09-22. Fresh source-only review of `81ec33b..b65c79a` then found M5-68
through M5-76. Those source blockers are corrected, and the complete local
M5-77 workspace/provisioned closure gate passed on 2026-09-22. Milestone 5 was
reopened by source-only review of `b95811b..168945a` on 2026-09-25, which found
M5-78 through M5-83. Those corrections and the complete M5-84 local closure
gate passed on 2026-09-25. A further source-only review of the same code found
M5-85 through M5-87: same-head advertiser deduplication, historical legacy
authority inference, and parity-only cold recovery coverage. M5-85 through
M5-87 are corrected, and the complete M5-88 local closure gate passed on
2026-09-25. Further source-only review found M5-89 and M5-90 in coverage-only
cold recovery: it matches sector IDs without checkpoint content authentication
and probes every overlapping current group. Those corrections and the complete
M5-91 local workspace/provisioned gate passed on 2026-09-25. A later source-only
review found M5-92 through M5-96: unbound claimed legacy roots, READY-target
quorum bypass, restore fallback on wrong-root placements, mixed-group coverage
loss, and retained-revision/audit root bypass. Milestone 5 is reopened;
Milestone 6 waits for corrections and M5-97. The follow-up commits through
`308b156` correct M5-93 through M5-95 and harden cold recovery, checkpoint
coverage, and audit. Source-only review found that checkpoint signing can still
accept an inconsistent revision-signed flat root and Merkle commitment through
a format-2 plan's root claim. M5-92, M5-96, and the local M5-97 gate remain
open on `308b156`. Commit `c7cc6fd` requires a replay-verified full-byte
binding for new legacy checkpoint coverage, including retained revisions.
M5-92 through M5-96 are corrected. Source-only review of `e64f76e` on
2026-09-26 finds M5-98 through M5-100: upgraded plans collide with durable old
attempt identities, unchanged group identities prevent replacing compact
evidence with full-byte proof, and raw witness bounds do not ensure CBOR
messages fit the peer frame. Those corrections and the complete M5-97 gate
remain pending; Milestone 6 waits.
The follow-up implements distinct attempt/group identities, authenticated READY
input reuse, compact version-three manifests, and encoded peer-message budgets.
Focused migration, checkpoint-signing, lifecycle, and transport regressions pass
locally. M5-98 through M5-100 are corrected; the complete M5-97 gate remains
pending, so Milestone 5 stays open.
The final source audit of `99c3c82` also found M5-101: root-bound legacy
coverage can accept a short information shard even though the V1 cipher and
restore require a complete 64 KiB sector. Correct the implicit length check
in signing, recovery, and audit before the final M5-97 gate. Packed variable
profiles retain their explicitly authenticated descriptor lengths.
Follow-up source-only review on 2026-09-26 also found M5-102: adaptive parity
upload sizes are bounded by the peer frame but can violate storage's 16-byte
alignment requirement. Round the budget down to complete Merkle leaves and
cover holder staging and interrupted resume before M5-97. At that review,
M5-101's length correction was uncommitted in the working tree. Milestone 5
remained open; Milestone 6 waited for these corrections and the final local gate.
M5-101 is now implemented: legacy coverage and recovery/audit require 64 KiB
ciphertext, while packed descriptors retain their explicit lengths. The
positive migration/lifecycle and negative short-proof regressions pass locally.
M5-102 and the complete final M5-97 gate remain open.
M5-102 is now implemented and its focused local regression passes. Adaptive
parity ranges are leaf-aligned, and frame-limited uploads survive encrypted
holder-storage reopening and reservation resume through finalization. M5-101
and M5-102 are corrected; the complete M5-97 gate remains open.
The corrected source `c7033fa` passed formatting, locked all-target workspace
tests, strict locked all-target workspace Clippy, and Docker lab safety locally
on 2026-09-26. The complete fresh disposable 8 GiB Btrfs/network acceptance
also passed at `4170dce`, whose changes from `c7033fa` are documentation only.
The five-daemon scenario passed owner/storage-only seed recovery and direct,
DCUtR, and forced relay bulk transfers. Cleanup and subsequent checks confirm
all disposable mounts, loop/image, namespaces, and daemons are gone. M5-97
is passed; Milestone 5 was closed at that point. All builds and runs
were local; no remote compilation server was used.
Source-only review through `515260c` on 2026-09-26 reopens Milestone 5 for
M5-103: a preserved incomplete retry monopolizes the coding worker even when
a stronger format-3 replacement is queued. An expired prepared retry is reused
forever and rejected at delegation; insufficient fresh coordinators also keep
the retry incomplete. New launches and activations are never reached. Correct
retry expiry/supersession and scheduling, then pass the new M5-104 local gate.
M5-97 remains passed historical evidence; Milestone 6 waits. This review ran no
builds, tests, daemons, runtime probes, or remote compilation.
The M5-103 follow-up is now implemented. Four real QUIC restart regressions
pass through verification, activation, checkpoint signing, staged cleanup,
and repeated reopen; retry rotation and late-evidence fences are also covered.
The complete final M5-104 gate remains pending, so Milestone 5 stays open.
Source-only review through `c4e97f8` finds M5-105 and M5-106: format-3 lane
coalescing can suppress a launch using failed/retired historical retry plans,
and its production caller stages inputs under an ID that coalescing never
dispatches. Both corrections are now implemented with passing production
restart/replanning regressions. The final M5-104 gate is pending; Milestone 6 waits.
The M5-107 verified-placement/epoch-identity follow-up also passes its focused
QUIC, migration, and core checks; the complete final gate remains required.

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
| Git-facing history, stage, and object map (Milestone 6) | The owner keeps Git-compatible commit/tree/tag bytes, refs, index, worktree state, and an object-ID-to-verified-anchors map keyed by root/filesystem in versioned local metadata. Committed reachable history and refs are included in encrypted owner-owned backup data so seed-only recovery can rebuild them; uncommitted stage state remains locally pinned until committed or explicitly discarded. A Git object ID is an interoperability identifier, not signed guild authority or a substitute for MutualBackup content verification |
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

Milestone 6's Git-facing object format is separate from these signed protocol
formats. A tracked regular file's Git blob is exactly the bytes captured at
`add`: no CRLF or other end-of-line normalization, clean/smudge/process filter,
`ident` expansion, or `working-tree-encoding` conversion on add, commit,
checkout, restore/reset, switch, merge, worktree creation, import, or export.
The immutable captured source is the source of truth for the blob, including
mixed line endings and non-text bytes; no intermediate normalized Git-index
payload may replace it. Git tree and commit objects still use canonical Git
serialization, while file payloads remain raw.
For a tracked file that the user has not edited, require byte identity across
the captured source, staged blob, committed blob, and every restored worktree
file. `status` and `diff` compare the working bytes with the raw staged and
committed blobs: changing only LF to CRLF (or back) is a real modification, not
an automatically corrected or ignored formatting difference. A merge result
intentionally written by the user or merge engine becomes a new raw-byte blob;
the frontend does not apply an additional conversion.
Incoming Git blobs become identical local file bytes; outgoing blobs retain
their original bytes and object IDs. Do not use `core.autocrlf`, `core.eol`,
`core.safecrlf`, or `text`, `eol`, `filter`, `ident`, and
`working-tree-encoding` attributes to rewrite payloads. Enforce this
independently of system, global, repository, and environment-supplied Git
config, and of attributes from `.gitattributes`, an attributes file selected
by `core.attributesFile`, or `.git/info/attributes` when importing an ordinary
Git repository. Treat transforming rules as inert when reading or writing file
content. A `.gitattributes` file is itself ordinary tracked bytes, but it does
not grant permission to transform other files. Never invoke an external filter
or write a converted temporary payload while checking such rules. Git object
IDs use the selected repository's canonical object framing
and hash algorithm, computed by the Git library from the immutable captured bytes.
Consequently, adding a file through our binary may produce a different blob ID
from stock Git's filtered `add` of the same worktree path. That difference is
expected: compare against `git hash-object --no-filters` on the source bytes,
and require ordinary-Git exchange to preserve object bytes and IDs rather than
emulate the peer's worktree conversion.
Retain MutualBackup's independent content roots and signed revision authority.

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
- **Portable private metadata and legacy guarded records:** native backends
  must preserve raw path bytes, supported ownership/mode/timestamps, sparse
  extents, and hard-link relationships under an explicit portable policy.
  Validate namespace topology and sector geometry before publishing a restore.
  Keep native inode IDs and anchor locators local. Guarded private formats 6/7
  are existing-state compatibility inputs, not a reason to retain a FUSE
  publication path or add new guarded features. Preserve their decoding and
  authenticated restore/export where required by the removal contract in
  section 4. Unsupported conversion must leave the original state intact with
  an actionable error; never reinterpret a legacy backend or discard its Git
  graph, ownership metadata, or retained sector recipes silently.
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

### Versioned source backend and Git local history (Milestone 6)

- Introduce a versioned source-backend boundary between local capture/restore
  and the existing revision/sector pipeline. Its durable contract identifies
  immutable source bytes, metadata, source filesystem capabilities, restore
  behavior, and reachability pins. Every backend must capture and restore file
  content byte-for-byte; a backend that cannot do so rejects the operation.
  For a staged file with source bytes `B`, its immutable anchor, Git blob
  payload, exported Git blob, and an unedited checkout must all contain `B`.
  If the working file subsequently changes, preserve its new bytes separately
  from the staged or committed blob. Backup and seed-only recovery must retain
  both states when protected; recovering history must not overwrite an unstaged
  edit to make the worktree match its Git blob. Share verified native anchors
  when the bytes match, and retain distinct sources when the bytes differ.
  A Git blob imported from an ordinary repository becomes the authoritative
  `B` for our checkout, regardless of that repository's attributes or the
  other client's worktree presentation. Native reflinks or clones may
  share physical extents, but no Git index, object database, pack cache, or
  worktree may retain a second permanent copy merely for compatibility.
  Git line-ending normalization and a configured clean filter are separate
  conversion paths; neither may change `B` at this boundary, even when an
  inherited Git setting or repository attribute enables it. The same rule
  applies to checkout, which must publish the stored blob bytes unchanged.
  Make raw-byte capture, import, and restore explicit operations of the
  versioned boundary. Keep attribute/configuration interpretation outside that
  payload path: a Git library adapter must consume the verified anchor bytes
  directly rather than pass a filename to an API that may apply conversions.
  New backend versions must preserve this contract, including across replay
  of an interrupted operation recorded by an older version.
  Verify the captured bytes before publishing an index entry or revision and
  the restored bytes before replacing a worktree file. A mismatch is an
  operation failure, never a reason to normalize line endings or run a Git
  filter to make the file match an expected blob. This contract also applies
  to future native Windows and macOS backends.
  Keep blocking filesystem work in bounded workers and keep the signed guild
  protocol independent of backend choice.
  The existing reflink root is the first implementation; Git history consumes
  that boundary, and native platform capture later implements it.
- `init` associates each Git repository with a stable protected-root ID and
  working-tree location, enrolling and probing a source backend before claiming
  backup protection. Keep the repository marker and Git-facing metadata in an
  app-owned `.mutualbackup` catalog while payload anchors stay in their
  filesystem-specific anchor areas. Exclude that catalog from ordinary tracked
  file scans and protect its reachable graph through encrypted revision metadata
  instead of recursively capturing itself. Reject initialization if that
  protection backend is unavailable; adding a worktree does not silently enroll
  its uncommitted edits. Bind catalogs and anchors to their native filesystem
  identities and verify those bindings before replay.
  Treat a pre-existing `.git` directory as a separate stock-Git repository,
  never as native history or a file tree to stage recursively. Any takeover of
  that worktree must be an explicit import with one catalog writer: import the
  Git graph by its stored object bytes, and capture current working files as
  their raw bytes. If stock Git filters made a worktree file differ from its
  stored blob, show that difference and require an explicit choice to stage it;
  do not quietly normalize the file or claim the two byte strings are one blob.
- Stage a regular file by first creating and durably recording an immutable same-
  filesystem reflink of the user's bytes. Hash that captured file through the
  Git library, record its blob ID, source locator, and index entry atomically
  or with crash-reconcilable intent, and never persist another copy merely to
  satisfy `.git/objects`. A later edit to the working file cannot change the
  staged bytes. Detect concurrent source changes during capture and fail or
  retry rather than recording mixed bytes. An unavailable reflink fails this
  capture path explicitly. Preserve sparse extents and file identity where the
  backend supports them. The index records
  the raw captured blob ID: Git configuration and attributes cannot normalize
  line endings or run a clean filter between capture and staging. On Btrfs,
  prove that the staged anchor initially shares physical extents with the
  source file and that a later source edit changes neither the anchor's bytes
  nor its Git blob ID. Equal logical sizes alone do not establish sharing.
  On Btrfs, separate logical file sizes from allocated physical extents: an
  anchor or checkout is a distinct file sharing the original extents, with
  new payload allocation on later writes through COW. Measure initial extent
  sharing and later isolation; do not require zero metadata allocation.
  A failed conversion-requesting command must leave the captured anchor,
  index, and working file unchanged; an inert repository attribute or config
  setting alone is not a reason to reject raw staging.
- Capture Git symlinks without following them: their blob bytes are the exact
  link-target bytes, and checkout recreates the link under the path-safety
  policy. Never treat a symlink as a regular-file reflink; explicitly reject
  unsupported gitlinks/submodules until their separate semantics are defined.
- Store Git trees, commits, tags, refs, and index metadata in the versioned
  local catalog; map a blob ID to one or more verified immutable anchors on
  their respective roots/filesystems. A custom Git object backend
  supplies Git-format bytes on demand and imports Git blob bytes into native
  anchors. Pin and collect each physical anchor separately so a same-filesystem
  checkout can use an available reflink without losing the last viable copy.
  Avoid a persistent second payload copy or Git pack mirror. A full
  read/hash pass and bounded transient pack buffers are acceptable; verify
  both Git object IDs and MutualBackup content roots, and reject an ID alias
  whose bytes disagree.
- For checkout or a second worktree, restore verified anchor bytes by reflink
  on a capable same-filesystem destination, preserving the exact blob bytes.
  Do not run a smudge filter, line-ending conversion, or encoding conversion
  while publishing a worktree file, including after a merge, reset, or pull.
  Never hard-link an editable worktree file directly to an immutable anchor:
  writing through that link would mutate the committed blob.
  Make any unavoidable cross-filesystem copy explicit and bounded, and do not
  confuse checkout copy policy with the no-silent-copy capture rule. Protect
  dirty or untracked worktree files from destructive checkout. Keep per-worktree
  HEAD/index state distinct while sharing immutable anchors safely. On Btrfs,
  verify extent sharing immediately after checkout and COW isolation after an
  edit in either worktree; the repository must not retain a second Git-format
  copy of the same payload to obtain that behavior.
- Back up the reachable Git object graph and refs as encrypted owner-owned
  content/metadata through the existing UserRevision pipeline, including
  commits on branches that are not checked out. A Git commit is only locally
  durable until a signed backup revision and checkpoint cover its graph; status
  must distinguish local history from guild-protected, seed-recoverable history.
  Recovery reconstructs the Git graph, refs, object map, and checked-out view
  from authenticated backup data without a cached local catalog.
  On a non-reflink recovery filesystem, stream verified Git blob sectors
  directly into one native anchor and preserve sparse zero ranges; do not
  require a temporary worktree payload and a reflink just to rebuild history.
  Restoring or exporting files onto a non-reflink destination does not qualify
  that filesystem for continuing capture. Re-enrollment requires a supported
  native backend and its complete probe.
- Represent explicit commit protection pins as namespaced Git refs so graph
  export, signed backup, and recovery retain their ancestry without another
  object format. Removing a branch or pin only changes reachability; physical
  deletion waits for the prune/GC gate and every retained revision. The local
  frontend has no implicit reflog protection until a durable reflog is defined.

### Remove the FUSE-backed guarded backend (R1)

The implementation withdraws enrollment/removal CLI commands
and rejects their legacy control requests. Startup now inspects the existing
encrypted catalog read-only before rekeying, schema migration, cleanup, or
replay, and rejects identified guarded roots, bindings, journals, and pending
capture/recovered-anchor plans. Source-loss recovery refuses guarded enrollment
before publishing its job. Serialized backend identities remain stable. The
[preservation procedure](docs/guarded-withdrawal.md) describes rejection and the
absence of a qualified migration tool. The mount runtime, supervisor, guarded
capture/publication and Git operations, link-freeze machinery, and `fuser`
dependency are removed. Minimal historical decoding and marker recognition
remain. Native seed recovery, retention/prune, and repeated owner-loss coverage
replace the useful generic guarded fixtures. Historical inventory with unavailable
metadata and verified mount-free export remain required; R1 is still open.

Available-input legacy export now reads signed files, preserved control catalogs,
explicit anchor areas and certified cached fixed/packed checkpoint data. A
separate read-only parity-volume reader validates historical schemas, existing
keys, owner signatures and bounded READY payloads without migration or rekeying.
Explicit `--parity-volume` inputs now supply fixed shards and variable information
or parity positions. Replay-verified transcripts bind variable geometry; all
reconstructed commitments, the coding equation, certified packed descriptors
and owner-signed output sectors are checked before publication. Explicit peer
inputs now reuse authenticated read requests through a separate temporary client,
preserving the withdrawn installation and requesting a decoding quorum after
local inputs. Missing checkpoint certificates can now be read from selected
peer heads; missing revision records require the preserved signed guild genesis
and a matching certified head. Paging, hashes, quorum and exact signed revision
checks apply without installing downloaded records. If the head does not contain
the requested record or placement, the reader follows certified parent hashes,
checking the same guild/genesis and exact preceding generation, and retries
missing/corrupt links across selected peers. History is streamed without storing
it in the preserved catalog. Missing packed coding transcripts can now be read
through signed event-page replay from the preserved genesis. The Add event binds
the complete verified transcript and group, or a historical unbound Add requires
a preissued quorum binding from its original signers. Attempt authority, packed
descriptor commitments, reconstructed codewords and owner-signed output remain
mandatory; no replay state or evidence is installed in the original catalog.
For a missing revision owned by a member admitted after genesis, replay signed
membership pages and require a historical prefix whose active roster, membership
epoch and quorum match the selected checkpoint. Membership records at that prefix
must include the owner; retained history remains exportable after removal. Removed
members may read checkpoint heads/pages and event evidence, but cannot use this
path to enroll or authorize mutations. Original-genesis owners and available local
exports do not require an extra membership-history round trip.
The read-only `legacy-list` command inventories authenticated available local
revision metadata from saved revision rows, legacy/scoped recovery heads and
certified checkpoint records. It deduplicates exact signed records, rejects
conflicting IDs/scopes/signatures, bounds the summary and reports per-revision
provenance. It neither reads ciphertext/source anchors nor proves exportability.
Explicit `legacy-list --peer NODE-ID=MULTIADDR` reads authenticated peer heads and
signed parent chains, binding the preserved guild genesis and using the export
path's later-member replay authority. Peer metadata joins the bounded, exact
signed-record inventory with separate provenance. Coverage reports unavailable
heads/parent links and unmatched owner authority; one-million checkpoint visits
bound recovery work. No peer evidence is installed in preserved state.
Its completeness flag remains false until remote history and preserved root/Git
catalogs, pins and pending intents can be reconciled; missing private metadata
must not be inferred from public signed revision formats.
Read-only recovery-directory discovery uses production Kademlia mailboxes and
live signed/encrypted bundles through explicitly selected `--bootstrap-peer`
contacts. Validate provider/subject/guild identity, signatures, expiry, encrypted
locator context, identity-bound endpoints and same-sequence conflicts. Treat
locators only as routes; checkpoint and membership authorization remains separate.
Support original and seed-wrapped rotated recovery keys without adopting key or
membership state. Directory queries have a 60-second deadline and existing
provider/record bounds, with at most 64 selected survivor identities. There is no
publication, enrollment, repair, durable observation or preserved-state mutation.
Complete retained-history/upgrade and broader relay/Tor discovery qualification
remain required.

The FUSE-backed guarded source backend is withdrawn. Remove its mount and view
implementation, enrollment and recovery publication paths, guarded Git
operations, backend-specific control commands, tests/probes, and `fuser`
dependency. Remove link-freeze/fanotify machinery used only by that backend;
retain unrelated native capture code and generally applicable safety checks.
Update CLI help, schemas, fixtures, acceptance scripts, packaging, and guides
with the code removal. Do not replace FUSE with another interception mechanism
or make chmod/hard-link freezing a fallback on unsupported filesystems.

Before deleting runtime paths, inventory existing root bindings, mount claims,
private formats 6/7, Git catalogs and pins, sector recipes, and pending capture,
release, recovery, and retirement intents. Provide a verified export or durable
migration to a supported native backend for existing protected data, or reject
unsupported state before mutation with an actionable recovery procedure. An
ordinary restore destination need not support continued capture. Keep user
files, staged/working differences, reachable Git history, and retained backup
anchors intact; retire them only under their existing reachability obligations.
Never assume a guarded anchor is trustworthy merely because it is readable:
verify retained bytes against authenticated content roots or reconstruct them
from peers before converting protected history.

Do not silently relabel `GuardedLinkFreezeV1` as `ReflinkV1`, renumber serialized
enum variants, or reinterpret old journals. Retain only the decoding and
offline recovery/export compatibility needed for old data; it must not mount a
view or authorize new guarded captures. Interrupted migration/export must be
replayable and preserve the original state until destination verification and
durable publication complete. If safe migration is unavailable, fail closed
without deleting the old data or automatically running the known-unsafe path.

Acceptance: ordinary native roots and Git still pass their existing gates;
new builds contain no FUSE runtime/dependency or guarded enrollment commands;
legacy-state fixtures either recover/export exact files and history without a
mount or stop before any mutation with a documented error. Include interrupted
handoff, retained revisions and pins, pending jobs, and no-space failures.
The retained-descriptor recapture defect and other canceled guarded features
are not separate implementation tasks; these checks protect existing data
during removal, rather than complete the withdrawn backend.

### Native source backends and platform work

- Linux uses qualified reflink capture with explicit rejection when the full
  immutable capture/edit/restore probe fails. Unsupported filesystems do not
  gain an unannounced eager-copy or hard-link fallback.
- Implement and qualify native Windows NTFS capture, including VSS where
  appropriate. Test service authorization, batching, diff-area headroom and
  eviction, and missing-snapshot reconciliation before relying on snapshots.
- Implement and qualify native macOS cloning, platform watchers, portable
  ownership/ACL/xattr handling, sparse files, and application-consistent hooks.
- Each supported backend must pass byte-exact Git and source-loss recovery
  gates as well as local capture/edit/restore and crash replay. Metadata and
  application consistency remain required even though FUSE is removed.

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
than a daemon prerequisite. Milestones 0 through 4 have passed. M5-123 through
M5-127 passed their recorded gate on exact code source `e09a13f`, but the later
source-only review found M5-128 through M5-130. Those corrections and focused
regressions are now committed through `39a99e7`. The complete local M5-131
gate passed on that exact code source; Milestone 5 is closed and Milestone 6
is next. The earlier M5-119 through M5-122 gate passed on `4880c28` and
remains historical evidence for that source.
M5-111–M5-113 and M5-115–M5-118 corrections passed
focused local validation and the complete locked workspace and fresh
Btrfs/network gates on exact source `720920d`. All compilation and execution
took place locally for that historical gate; this review is source-only.
The previous final M5-104 workspace and fresh provisioned gate passed on
`f8e47d3`, with all
disposable resources removed and independently checked. This remains
historical evidence for that source tree.

Earlier correction history: Milestone 5's historical M5-67 gate passed, and
the later M5-68 through M5-76 source blockers
in checkpoint catch-up, legacy migration, incremental packing, and relay
expiry are corrected. The complete local M5-77 closure gate passed on
2026-09-22, but source review found M5-78 through M5-83 and reopened Milestone
5. Those corrections and the complete M5-84 local gate passed on 2026-09-25.
Further source-only review found M5-85 through M5-87 and reopened Milestone 5;
M5-85 through M5-87 are corrected, and M5-88 passed locally on 2026-09-25.
Another source-only review found M5-89 and M5-90. Their corrections and the
complete M5-91 local gate passed on 2026-09-25. A further source-only review
found M5-92 through M5-96, so Milestone 5 is reopened and Milestone 6 waits
for the correction and closure gate. M5-91 remains evidence for its exact
source tree. Source-only review of `e64f76e` on 2026-09-26 finds M5-98 through
M5-100 in the stronger legacy proof's migration and encoded-frame handling;
these also require correction before M5-97 and Milestone 6.
The final correction series through `c7033fa` now passes the complete M5-97
local workspace and fresh disposable Btrfs/network gate. Milestones 0 through
4 are passed. Subsequent source-only review found M5-103 in same-epoch durable
retry scheduling. Its correction and focused restart regressions now pass.
Follow-up source review through `c4e97f8` finds M5-105 and M5-106 in retry
coalescing and staging. Those corrections and focused restart/replanning
regressions now pass. Milestone 5 remains open and Milestone 6 waits for
the complete M5-104 gate. Source-only review through `1f3141e` also requires
M5-108/M5-109: safely renew expired durable launches and give deferred launches
bounded scheduling turns. Both corrections and all 21 focused tests pass.
Source-only review through `16c28a5` finds M5-110: acknowledged launches
are skipped after expiry if their coordinator disappears. Correct this
delegator recovery gap before the complete new local gate. M5-110 is now
implemented and its coordinator-loss, accepted-result, and lineage regressions
pass locally; the complete M5-104 gate remains pending. The preceding
records are closure history.
Later wire or durable-state changes
require the review and gate of the milestone that owns them. Build and run all
subsequent validation locally; do not use a remote compilation server.

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
- The Milestone 6 Git-compatible binary presents the supported basic Git
  command syntax but sends stateful operations through the same versioned local
  control boundary; `mutualbackupd` remains the sole live catalog writer.
  Keep command parsing, Git object semantics, durable source capture, and
  asynchronous backup jobs distinct. Unsupported Git commands and options that
  request content conversion fail explicitly. Existing byte-changing attributes
  and configuration remain inert for payload bytes, so raw-byte commands still
  work; never delegate them to a stock Git process that would create an
  untracked second object store or transform file content.
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
after in-flight transitions finish. Native source and catalog retirement must
remain replayable. Virtual-zero ranges may be omitted
only when authenticated state proves that all `k` information roles, and thus
all linear parity roles, are exactly zero. Secure physical erasure cannot be
proved on remote hosts, COW filesystems, or SSDs; deletion ends the obligation
and requests best-effort removal.

For Git-backed roots, live refs, the staged index, open worktrees, protected
commits, retained signed backup revisions, and in-flight jobs all pin their
reachable anchors and metadata. A Git-facing prune/GC operation first updates
the protected graph with a durable intent, then removes only data unreachable
from every such root after the ordinary retention and peer-cleanup obligations
finish; it must not merely hide commit names. Report logical deletion and
physical space returned separately, because Btrfs extents may still be shared
with another reflink or the working file. Reflog/history-expiry behavior and
explicit protection pins must be documented before deletion is enabled.

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

Each milestone extends the same runnable product. Preserve the daemon/control
split and real data/network path; the Milestone 6 Git-compatible command binary
uses that same live node rather than a parallel replacement. Pause for a focused
source, runtime, security, and usability review at every gate before committing
the next milestone's detailed scope.

**Current position (2026-10-16):** Milestones 0 through 5 have recorded passing
gates; Milestone 6 remains open. The accepted direction removes FUSE-backed
guarded capture and Git integration. Prior milestone passes do not close the
new non-FUSE production findings below. Continue native Git, source-backend,
platform, metadata, watcher, and application-consistency work; each content
operation still requires exact bytes, crash/reopen safety, and native-anchor
storage evidence. Complete graph recovery and physical pruning alongside those
requirements. The recorded implementation and runtime results that follow the
current correction queue are historical, including any superseded statements
that guarded completion is required.

Source review on 2026-10-26 of `76105a8..a581995` confirms progress in durable
native Node/control/parity ownership, shared process-local SQL admission,
transactional volume configuration and resumable additional native volumes.
The reviewed ownership/configuration paths contain no newly confirmed data-loss
or unauthorized-publication defect. Two P2 corrections are required:
R3-NATIVE-RECORD-QUOTA-RESTART must resume interrupted parity record-quota adoption
in the managed opener before reconciliation, and R5-VIRTUAL-ZERO-ROUTING must
include virtual-zero owners whose signed openings are required. `TODO.md` records
both source findings and regression requirements. Correct them before qualifying
current source and installed artifacts; existing legacy quota-restart and 1+1
routing regressions do not cover these cases.
The `30cff18` complete-source pass is historical after the musl ioctl correction
in `faeb44d`; the corrected packaged build and current merged qualification are
still pending. CLI/default policy selection, managed rekey/adoption, enclosing
funding, normal paged integration and R1/R2/R3/R5/R7 remain open. Deferred dense
capacity and native-platform acceptance requirements are unchanged. The tree
was clean at review start. This pass ran no builds, tests or runtime probes;
execution claims below remain their separately recorded historical evidence.

Follow-up source review on 2026-10-16 of `4065dba..7c63600` confirms progress
toward M6 through shared traversal/scratch ownership, retained-anchor preservation
and explicit native SQL physical admission. No new severe defect was confirmed
in the reviewed paths, including the local SQLite/SQLCipher extensions and key
policy dispatch. The physical Store APIs and authenticated format-2 readers are
not yet normal persistent startup enrollment; mutable Node startup still rejects
format 2. Complete durable creation/restart/adoption and shared resource
reservations before enabling normal paged producers. `TODO.md` now tracks those
next integration steps and the stale vendored bridge contract explicitly.
The later complete-source pass on `d8e0581` and ordinary Node pass on `efbe298`
are recorded historical evidence, not qualification of all current merged code
or an installed artifact. R5 causal diagnosis and the other M6 gates remain open.
The tree was clean at review start; no builds, tests or runtime probes ran in
this pass.

Source review on 2026-10-16 of `28e863c..fb19875` confirms the retained-writer
recovery correction. Original key authentication remains in body admission;
both layouts run the complete predecessor transition before publication, so new
revisions still require current authority. The regression source now covers
authority changes before successor creation, hostile revisions and restart
reconstruction. No new severe defect was found in the reviewed changes. Timeout
diagnostics preserve the original deadlines, assertions and successful cleanup.
The working tree was clean at review start; this pass ran no builds, tests or
runtime probes. Focused qualification is recorded below, but the latest complete
source gate failed its first network-coverage wait and installed jobs did not
start. Diagnostic reruns establish no cause and do not close R5/R7 or M6.

The 2026-10-15 source review of `e36afa7..6001cdd` and the Linux parity-volume
handoff now committed as `e619290` found substantive progress in shared quotas,
durable packing custody, retained native/Git restore and seed-owned checkpoint
acquisition. Normal paged producers remain disabled; these explicit staged APIs
do not close the complete production pipeline. The review found one new P2
recovery blocker: acquisition/proof reconstruction required every retained
writer fence to remain current, rejecting legitimate successor checkpoints that
retain unchanged revisions after writer rotation, revocation or owner removal.
The required correction was to preserve original-key authentication and use the
complete predecessor transition to enforce current authority for new mutations.
It is now implemented in both layouts; see R3-RETAINED-WRITER-RECOVERY in
`TODO.md`. No new data-loss or unauthorized-publication defect was confirmed in
the reviewed paths. Volume-handoff qualification was pending at that review;
the subsequent focused qualification is recorded below. That pass ran no builds,
tests or runtime probes; previous runtime evidence remains limited to its
recorded inputs.

Source review of `6c10666..e36afa7` on 2026-10-10 confirms the preceding review's
two recovery-inventory findings are corrected: supported long Git refs and
validated discovery assistance now pass inventory and safe placement, while
unknown ownership still blocks placement. The reader ownership-lifetime fix is
committed, with atomic path/directory handoff still open. No new severe
regression was found in the reviewed inventory, ownership and P2P shutdown
changes. This pass ran no builds, tests or runtime probes. Recorded debug-source
qualification remains separate evidence; it does not establish installed
release-artifact qualification or close Milestone 6.

Linux reader directory binding is now qualified separately from the earlier
source review. Saved control and parity readers retain their original directories
through rename/replacement, and SQLCipher WAL/SHM operations retain the same
capability. The concrete before-fix regression and the complete ordinary run are
recorded in R1 of `TODO.md` and the production catalog ADR. This increment passes
1,326 distinct cases, including the provisioned sparse Btrfs case, with frozen
source and binary hashes. Complete admission/leaf/version handoff and all other
open Milestone 6 gates remain required.

Initial Linux control writers now check admitted catalog/journal/key versions
and SQLite's opened main inode before writable configuration. Read-only key
selection carries forward through interrupted rekey completion; orphan journals
without a catalog reject before startup ownership changes. R1 records the actual
before-fix reproduction and 1,334 distinct passing source cases. This qualifies
the initial control handoff; complete namespace/volume/external-owner handoff and
the remaining Milestone 6 gates remain open.

Independent read-only authority/history lookups now use short, composable SQLite
snapshots. NodeReader control connections are now query-only, so this applies
to the actual concurrent reader route while keeping its directory lease.
Deterministic valid-publication interleavings reproduced the exact
false stale-authority error from the native baseline before the correction;
a separate regression keeps the final publication fence enforced. The R5
fixture qualifies a real relay-only signer partition, coordinator crash,
stopped-catalog cryptographic proof, and same-event recovery with all five
original signatures. All 380 ordinary Store, 527 ordinary Node and 23 ordinary
process cases, the default topology and two fresh fault runs pass on frozen
debug source: 932 distinct cases in 933 executions, with cleanup verified.
The identical Store binary retains its 380 verified passes. The remaining 553
positive executions, including the default topology, run freshly. Completed
activation records also resume their exact authenticated next bound Add after
restart; a valid-history regression reproduces the former skip and preserves
the original proposal/signatures and full-signature requirement. The cleanup
check also preserves that exact unfinished Add instead of treating its absent
group as forgotten; explicit replan markers remain enforced. The original
stall diagnosis, complete fault matrix and remaining installed artifact gates
remain open; see R5 in `TODO.md`.

Existing paged data can now enter retained-source quota policy through a bounded
initial ownership scan. Signed publication, original verified source facts,
recipes and physical pins must reconcile; shared and cancelled owners are charged
before the policy commits. Frozen source qualification passes 735 distinct cases,
including both preconfigured and post-migration quota Btrfs recovery variants.
See the quota adoption item in `TODO.md` and ADR 0002. Complete enclosing metadata/
physical admission, normal paged producers and seed recovery, current installed
artifacts and the user-deferred dense/platform gates remain open.

Retained paged checkpoint certificates and public pages now have a bounded,
authorized peer-read path. Exact local ownership and authenticated root-to-page
edges are checked in a query-only snapshot; clients independently verify the
original certificate and requested page. Frozen qualification passes all ordinary
workspace targets and both provisioned Btrfs cases (1351 distinct tests), with
23 unchanged qualified binaries. This enables retained candidate transport;
normal producers, complete admission/distributed readiness, atomic activation,
the remaining installed-artifact matrix and deferred dense/platform gates remain
open.
See the retained public transport item in `TODO.md` and ADR 0002.

The installed Linux runtime and Git alias on `7d0edb3` now pass packaging,
ordinary process/raw-path/stock-Git checks, five-daemon seed recovery, and two
fresh real relay-signer partition/coordinator-crash runs: 27 distinct process
cases in 28 executions plus three Git packaging scenarios. Both fault runs
cryptographically verify the original stopped-catalog signatures and transcript,
then require the same event with all five original signers before commit.
All 320 source files match the immutable Nix build input; wrappers, static
payloads, alias and frozen drivers remain unchanged, and native/network cleanup
is verified. The earlier 1,351-case workspace result retains identical code
inputs and all 23 binary hashes. See R7 in `TODO.md` and ADR 0002 for the exact
scope and `/tmp/mb-m6-installed-7d0edb3-c4pmnqci` evidence.
The mandatory packaged runner now invokes the controlled fault scenario twice,
requires bounded original-signature proofs correlated to the actual relay
dispatch and missing signer, rejects reused request IDs, and checks network
cleanup after each run. Eleven boundary checks and both retained real installed
proofs pass the gate. Workspace/all-target driver compilation preserves the
qualified debug configuration: actual locked all-target compilation leaves all
23 previously qualified binary hashes unchanged. Application processes use the
installed candidate.
Fresh exact-source qualification on `d80c108` passes the pinned Nix musl
build, all three isolated-PATH Git packaging scenarios and the complete mandatory
installed runner: 23 ordinary process cases, raw Unix paths, the stock-Git bridge,
five-daemon topology/seed recovery and two fresh relay signer partition and
coordinator crash runs: 27 distinct process cases in 28 positive executions. The
baseline passes in 774.93 seconds; the two interruption runs pass in
711.91 and 742.50 seconds. The runner validates both original-signature
proofs with distinct request IDs and checks network/forwarding cleanup after
each run. Each proof authenticates the original four signatures and transcript
from a separate complete stopped DB/WAL copy, preserves original stopped inputs,
and requires the same event/attempt with all five original signers before backup
commits. Both fresh interruptions occur before activation completes; they do not
add installed coverage of the completed-activation retry branch. All 320 tracked
source files match the immutable Nix source; installed wrappers/payloads/alias
and both frozen test drivers stay unchanged. Independent
live daemon observations identify the installed static payload on all five peers.
The final independent audit verifies source/candidate/driver identities and
network, forwarding, mount, loop and image cleanup. Workspace/all-target driver
compilation preserves all 23 previously qualified workspace binary hashes;
identical Rust/dependency inputs retain the earlier 1,351-case qualification
without rerunning it. Auxiliary uncommitted work and all installed roots are
preserved. Evidence, exact case inventory, private peer logs and independent
audits are retained under `/tmp/mb-m6-installed-d80c108-4hjjpv1t`.
The historical stall diagnosis and full fault matrix, remaining release matrix,
complete metadata/physical admission and normal paged recovery remain open.
Dense 1 TiB and native Windows/macOS qualification remain user-deferred.

### Production corrections from the 2026-10-05 source review

These are the correction requirements; completed increments are recorded below.
`TODO.md` owns their open status and evidence. Retain existing passing safety
checks while adding the specific missing behavior.

| Priority / task | Required change | Acceptance evidence |
| --- | --- | --- |
| R1 — remove FUSE | Execute the removal and existing-state contract in section 4. Cancel guarded recapture repair, guarded Git completion, and FUSE platform probes. | No FUSE runtime/dependency/enrollment path; native regressions pass; legacy data is verified and preserved or rejected before mutation. `legacy-list` format 18 reconciles preserved root/backend/Git registrations, guarded captures, pending capture/recovery plans, Git graph intents, retained native anchor/retirement records and cached area locations with available signed revisions in one bounded local snapshot. Inventory and placement preflight forbid journal creation; closed immutable reads detect source changes and live WAL pairs retain read snapshots. Earlier local-state qualification passed 322 cases; pending capture/recovery ownership passed 336. The graph/native-owner increment passes 444 unique cases, including 282 ordinary store and 100 ordinary Git cases, 36 inventory/export/peer cases, 19 ordinary CLI process cases, discovery/compatibility checks and three provisioned Btrfs regressions. All four debug programs build; formatting and strict workspace Clippy pass, source and eight binary hashes remain unchanged, and native fixture cleanup is verified. Other ignored fixtures and installed-artifact qualification remain open. Peer-client and catalog-export placement exclude known local source/Git/anchor/cache inputs, aliases and stable identities of renamed roots; unverifiable possible identities reject before client or output creation. Export retains the checked parent capability through recovery and publication, including explicit file mode, and rejects parent replacement before staging/publication; destination/pinning qualification passes 61 unique export/peer/discovery/compatibility/CLI/Btrfs cases, with all four debug program builds, format, strict workspace Clippy, unchanged source/six-binary hashes and native fixture cleanup verified. Peer-client/export placement also excludes saved unselected parity volume locations, including retired/unconfigured entries, through the original current/historical registry decoder without opening manifests or payloads. It shares paged scratch admission’s 4 MiB/1,023-record bounds and validates all records before using paths; relative/invalid paths, escaping database names and duplicate UUIDs reject before creation. Real Node fixtures cover closed, WAL-only and live catalogs, raw volume paths, descendants/aliases and unchanged original file sets/bytes; codec/size/count boundary fixtures also pass development checks. Saved-volume placement qualification passes 159 unique cases: 39 export/peer cases, all 61 ordinary volume cases, all 32 ordinary paged cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-volume-placement-validation-kowi9nmv`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 5 now includes saved storage-volume registrations from the same bounded decoder and local snapshot: raw paths, UUIDs, database names, state, configured status and budget/headroom; wrapped keys are omitted. Historical configured defaults retain `configured_recorded: false`; retired/unconfigured entries remain included without asserting payload custody or history completeness. Entries share the full 32 MiB report budget, with exact/over-limit and original-codec/raw-path/state/CLI fixtures. Storage-volume inventory qualification passes 128 unique cases: 40 export/peer cases, all 61 ordinary volume cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-volume-inventory-validation-gdx0ells`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 6 adds all eight saved control-catalog volume custody record kinds through the original layouts and shared canonical/shape/key validation: fixed/variable receipts, write/staged-attempt intents and receipts, reservations, retirements, variable migrations and copy cleanup. Original keys/hashes and decoded attempts/commitments/cleanup/source-destination ownership retain references without registry entries; they do not authenticate custody or resolve pending work. SQL rows remain bounded (512-byte fixed records, existing 32 MiB cleanup-list rows), and entries share the complete 32 MiB report limit. Original-wire closed/WAL-only/live fixtures preserve bytes/file sets; JSON round trips, invalid shapes/keys, noncanonical/oversized rows, missing registrations, report bounds and corrupt late placement records are covered. Payload verification and history completeness remain false. Volume custody inventory qualification passes 131 unique cases: 41 export/peer cases, all 63 ordinary volume cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-volume-ownership-validation-o4_qqllw`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 7 includes original unversioned local-sector recipes and all four append-only source variants: legacy/stable anchors, Inline and private catalog pages. Shared canonical/key/shape validation retains the existing 68 KiB SQL row bound. Guild/sector/ciphertext-root identity, geometry and source metadata share the full 32 MiB report budget; Inline exposes length only and preserves valid zero-length synthetic filler. Absolute recipe-only area hints and aliases exclude placement, while relative historical hints retain their status and filesystem-root discovery hints are not whole-filesystem exclusions. Recorded filesystem words do not establish stable relocated ownership. Original-wire closed/WAL-only/live, raw-path/JSON/Inline-privacy, malformed geometry/path/key/row, exact/over budget, late corruption, recipe-only placement and real CLI filler fixtures are covered. No source payload is opened, and payload/history verification remains false. The initial qualification retained under `/tmp/mb-m6-local-sector-validation-rvsv40wf` exposed a CLI fixture write after read-only shell inspection. Filler creation now precedes inspection; recipe production code is unchanged. Local-sector recipe qualification passes 135 unique cases: 45 export/peer cases, all 63 ordinary volume cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-local-sector-validation-m858b2w1`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 8 inspects saved linked-worktree records in available external Git catalogs through per-repository keys, pinned private directories/markers and non-creating metadata snapshots. Original Preparing/Ready/Removing states preserve raw paths, recorded identities and target branches without native admission, selected-HEAD repair, source-file access or removal replay. Shared inventory/placement validation rejects conflicting namespaces/markers, malformed keys/records, orphan journals and the existing 256-worktree cap; paths, aliases and both interpretations of recorded native root identities exclude destinations, including renamed worktrees. Rows retain the existing 32 MiB local bound, and report entries share the complete 32 MiB summary budget. Catalog availability and linked-worktree coverage are separate from complete catalog inventory, payload verification and retained-history completeness, which remain false. Original-wire closed/WAL-only/live/all-state/raw/renamed/alias/JSON fixtures and missing-root/catalog/key/namespace/count/budget/late-corruption cases preserve original inputs. Each external snapshot remains separate from the local control snapshot; this is not atomic multi-owner admission. The actual CLI fixture inventories an original Preparing record and rejects worktree/alias export and scratch parents without changing either catalog or working files. External Git worktree qualification passes 240 unique cases: 46 export/peer cases, all 63 ordinary volume and 104 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-git-worktree-validation-xaclttn_`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 9 adds original external Git object-to-anchor mappings, primary/linked indexes and cached area locations to the same per-repository snapshot as linked worktrees. Original native/withdrawn root-backed/imported file manifests use the existing versioned codec and preserved ownership checks; scope/raw path/OID/mode/anchor IDs and locator/identity provenance remain visible, including indexes without linked registrations. Relative cached hints are not resolved against cwd. SQL rows retain the 32 MiB object, 512-byte index and 4,112-byte cached-location bounds; index/location paths are limited to 4,096 bytes, and all projections share the full 32 MiB report limit. Source/area/absolute cached hints and aliases exclude export/scratch parents without payload/working-marker reads or replay. Separate family coverage flags keep full catalog/payload/history verification false. Original-wire closed/WAL-only/live, all-manifest/scoped/raw-path/missing-payload/relative-hint/alias/JSON, malformed namespace/key/path/geometry/encoding/row, exact/over report budget, late corruption and actual CLI fixtures preserve original inputs. External Git anchor/index qualification passes 242 unique cases: 47 export/peer cases, all 63 ordinary volume and 105 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-external-git-owners-validation-is_jr74i`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 10 adds original external refs/pin-namespace status, every stored commit/tree/tag metadata object and explicit primary/linked HEAD records to each repository snapshot. Namespace parsing is shared with indexes; sorted repository UUID lookup replaces repeated linear status searches. Named pin-prefix refs accepted by the original graph importer remain visible with explicit generated-OID/name-match status. Absent HEADs do not synthesize or write `main`; saved branches retain their original scope. Canonical/version/kind/key and SHA-1 content-address checks open no Git scratch repository or source payload. Metadata summaries expose size/hash, while ref-target/full-graph reconciliation and full catalog/payload/history flags remain false. SQL limits are 512-byte ref rows/8 KiB names, the original 64 MiB metadata payload bound plus 1 KiB encoded overhead/20-byte keys, and 2 KiB HEAD rows with 1,024-byte branches; all projections share the full 32 MiB report limit. Original-wire named/generated pins, absent/explicit/scoped HEADs, exact/over limits, malformed key/namespace/version/kind/encoding/hash, closed/WAL-only/live, raw tree paths, unreachable metadata/unknown refs, JSON/report budget, late corruption and actual CLI fixtures preserve original inputs. External Git ref/metadata qualification passes 244 unique cases: 47 export/peer cases, all 63 ordinary volume and 107 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-git-history-validation-12rl_xwe`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 11 adds original unfinished regular-file staging intents from primary and linked external Git scopes. The unchanged ReflinkV1, guarded link-freeze V1 and raw ReflinkV2 plan layouts are inspected without backend admission, source/anchor access, capture or replay. Plans retain capture/area UUIDs, raw source/relative/area/volume hints, logical lengths and recorded/stable root/file identity provenance; unchanged native identity layouts remain unknown, while the original guarded plan establishes stable IDs. Canonical/version/namespace/key/path/mode and plan-shape checks share one reader for inventory and placement; SQL paths are bounded to 4,096 bytes and intent rows to the existing 32 MiB bound. Complete stage projections share the full 32 MiB report budget. Known source/area hints, aliases and recorded/stable renamed source roots exclude export/scratch parents; volume roots remain discovery hints. A separate regular-stage coverage flag leaves full catalog/payload/history verification false. Original-wire plan variants, malformed shapes/scopes/keys/versions/modes/encoding/rows, staging-only ownership, closed/WAL-only/live catalogs, raw paths, renamed roots, aliases, exact/over report budgets, JSON, late corruption and the real CLI preserve original inputs. External Git regular-stage qualification passes 538 unique cases: 48 export/peer cases, all 292 ordinary store, 63 ordinary volume and 108 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and eight program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-regular-stage-validation-sciir69g`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 12 adds original unfinished primary/linked symlink-stage journals, preserving both the implicit catalog root in version 1 and the explicit catalog root in version 2. The original decoder, canonical re-encoding and bounded SQL key/row reads retain scope, raw source/relative/catalog hints, recorded source/root/catalog/temporary identities, temporary name and optional native/guarded/raw file capture plan. Captured symlink target bytes remain private: summaries expose only length and BLAKE3 digest. Validation opens no working symlink, source, temporary input or anchor and never admits a backend, captures or replays the operation. Root/catalog hints and identities, plus optional plan source/area ownership, exclude export/scratch parents including aliases and renamed roots. A separate symlink-stage coverage flag leaves full catalog/payload/history verification false, and complete projections share the full 32 MiB report budget. Original-wire tests cover both versions before temporary creation, after creation and after each supported plan is saved; closed/WAL-only/live catalogs, raw paths, renamed roots, aliases, JSON/target privacy, exact/over report budgets, malformed keys/scopes/paths/identities/versions/target geometry/plans/encoding/rows, late corruption and the real CLI preserve original inputs. External Git symlink-stage qualification passes 248 unique cases: 49 export/peer cases, all 63 ordinary volume and 109 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-symlink-stage-validation-w3ygmtna`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 13 adds original external Git prune batches and primary/linked tracked-removal intents to each preserved repository snapshot. The original positional codecs retain every retired native, imported and withdrawn root-backed file manifest, plus removal scope/path/indexed-anchor and recorded root/file identities. Prune records omit object IDs, so reports do not invent an OID association. Empty metadata-only batches and the original 1,024-anchor limit remain valid; canonical/key/namespace/version/shape/identity and duplicate-anchor checks open no payload, working path or ownership marker, and never replay removal, discover areas or perform physical pruning. SQL uses the existing 32 MiB prune-row bound and 4,096-byte stage-path limit; removal rows are bounded to that path plus 1 KiB fixed-field allowance. Complete projections share the full 32 MiB report limit. Prune source/area hints and aliases, and recorded removal roots including renamed or unregistered linked roots, exclude output/scratch placement. Separate family coverage flags keep full catalog/payload/history verification false, with missing index/object/worktree joins visible as unfinished ownership reconciliation. Original-wire native/guarded/imported manifests, empty/exact/over batches, primary/linked removals, malformed records/keys/scopes/IDs/paths/encoding/rows, closed/WAL-only/live catalogs, raw paths, aliases, renamed removal roots, JSON/report budgets, late corruption and the real CLI preserve original inputs. External Git retirement qualification passes 251 unique cases: 50 export/peer cases, all 63 ordinary volume and 111 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-git-retirement-validation-woqwv_9q`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 14 adds original linked-worktree removal journals independently of their saved registration, selected HEAD and index. The original v1 positional codec retains repository/worktree scope, root/parent/marker-directory/marker identities, every raw file path/OID/mode/identity and every child-directory path/identity. Pure bounded decoding enforces the original 256-worktree and 8,192-file/directory limits, 4,096-byte paths, canonical namespace/key/version/encoding, nonzero identities, same-root-filesystem owned entries, valid modes and unique normalized non-NUL paths. It does not open a worktree, read its marker, repair its HEAD, unlink files or replay removal. The complete projected report shares the 32 MiB limit. Recorded root, marker-directory and child-directory identities exclude output/scratch placement after rename or relocation, including historical device and stable-filesystem identity eras and aliases. The containing parent is location metadata rather than an owned root. Separate family coverage keeps full catalog/payload/history verification false and leaves absent registration/index joins unresolved. Original-wire, empty/exact/over cardinality and path/row bounds, malformed ownership, closed/WAL-only/live catalogs, relocated directories, JSON/report limits, late corruption and actual CLI checks preserve original inputs. The initial worktree-removal qualification passed all 233 non-process cases and 19 CLI process cases, but candidate selection returned Linux ETXTBSY while executing a freshly written test script. The fixture now executes the existing `/bin/sh` through installed-candidate symlinks and explicit marker commands, preserving raw-path and candidate-only assertions without writing an executable. The exact competing writable descriptor was not captured. The failed attempt, unchanged 284-source/seven-binary hashes and verified native cleanup are retained under `/tmp/mb-m6-worktree-removal-validation-rvn03s52`. Continuation qualification reuses only passing cases on identical production code and identical Node/Git/program binaries, and reruns the complete CLI process suite on the rebuilt driver. External Git worktree-removal qualification passes 253 unique cases: 51 export/peer cases, all 63 ordinary volume and 112 ordinary Git cases, 20 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two provisioned Btrfs identity/retained-capture cases. The continuation reruns all 20 CLI cases after correcting the executable fixture and reuses 233 passing cases on identical production code and six unchanged binaries from the retained first attempt. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged during the continuation, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-worktree-removal-validation-continuation-phcwl26e`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. `legacy-list` format 15 includes original external Git fetch versions 1/3/5/6, branch/tag push wrappers, standalone blob-import plans and fetch-verification rows. Pure bounded readers validate canonical original namespaces/keys/layouts, source/target path hints, original graph/reference limits, metadata content hashes, blob shapes, push binding, root capture ownership and sorted nonnil verification anchors. They do not open stock Git, replay imports, read payloads or infer a fetch UUID for blob-import rows that never recorded one. Projected metadata exposes byte lengths and hashes; the complete report and every nested item share the 32 MiB limit. Separate family coverage leaves full catalog, graph/payload verification and retained-history completeness false; historical verification evidence is retained without treating it as current payload proof. Placement excludes recorded source/target/root/area hints and renamed import-root identities in both device and stable-filesystem eras, including aliases. Physical verification-anchor joins and relocated areas without recorded directory identities remain unresolved. Original-wire fixtures cover all versions, missing enclosing fetch records, malformed scope/key/version/path/object/plan/anchor data, cardinality/row limits, closed/WAL-only/live catalogs, JSON/privacy/report bounds, unchanged inputs, late corruption and actual CLI placement. External Git fetch/push qualification passes 549 unique cases: 52 export/peer cases, all 293 ordinary store, 63 volume and 113 Git cases, 21 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and eight program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-fetch-inventory-validation-yig_0e3e`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native Node suites, installed artifacts and other platforms were not rerun. `legacy-list` format 16 adds original primary and linked-worktree merge sessions and generated-blob intents. Pure canonical v1 session/blob codecs retain linked envelope identity, branch/source-ref/commit scope, sorted conflict and resolved paths, generated input/result OIDs and modes, and original blob-import root/area ownership. Session author names, email addresses and messages expose only byte lengths and hashes. Readers reuse original session rules, the 8,192-conflict limit, normalized 4,096-byte paths, original 1 MiB generated-blob bound and 32 MiB rows; they neither open anchors/worktrees nor resume or regenerate a merge. Missing session/index/worktree/payload joins stay visible, and family coverage leaves full catalog/history and payload verification false. Every nested projection shares the full report limit. Placement excludes original source/area hints and recorded renamed import roots in both filesystem-ID eras, including aliases; relocation without a recorded directory identity remains unresolved. Original-wire primary/linked/orphan cases, malformed scope/key/envelope/path/mode/session data, exact/over path/count/size limits, closed/WAL-only/live catalogs, private-text/JSON/report limits, late corruption and actual CLI exclusion checks preserve original inputs. External Git merge qualification passes 258 unique cases: 53 export/peer cases, all 63 ordinary volume and 114 Git cases, 21 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-merge-inventory-validation-0oas_ncm`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native Node suites, installed artifacts and other platforms were not rerun. `legacy-list` format 17 inventories original checkout/restore/reset versions 1 through 11 and linked-worktree envelopes 1 through 3. Pure version-specific decoders and original writers preserve canonical positional layouts, including separately serialized old native-content roots and version-11 selected paths, target index and prior-index digest. Reports retain original branch/ref/commit selection, preparing/applying/cleanup phase, staging name/identity, every old/new file OID/mode/anchor/identity, staged and removed directory identities, native length/hash and linked root identity. Primary journals never recorded a root directory ID and keep it absent; older unanchored files without native roots remain unverified. Original 8,192-entry family and 4,096-byte path limits, 32 MiB rows, canonical scopes/keys/envelopes, nonzero recorded identities and file/index shapes validate before report or placement. Every projected nested item shares the complete report limit. No worktree, staged file or anchor is opened and no checkout, index/ref update, restore or reset is replayed. Placement excludes recorded linked roots, staging directories and staged/removed child-directory identities after rename or relocation, including both filesystem-ID eras and aliases. Complete physical file/anchor/root joins, especially relocated primary roots without a recorded directory ID, remain unresolved. Original-wire all-version/envelope/phase cases, exact/over path and all family cardinalities, malformed originals, closed/WAL-only/live catalogs, JSON/report bounds, late corruption and actual CLI placement preserve original inputs. Family coverage leaves full catalog/history/payload verification false. External Git checkout qualification passes 260 unique cases: 54 export/peer cases, all 63 ordinary volume and 115 Git cases, 21 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-checkout-inventory-validation-b89n2aw8`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native Node suites, installed artifacts and other platforms were not rerun. `legacy-list` format 18 exposes original Git source-backend bindings and every unclassified external-catalog row. The original private v1 binding retains repository UUID and backend only; it records no root identity and absence never synthesizes one. Its bounded canonical reader accepts historical withdrawn backend metadata without invoking enrollment or replay. Unclassified records expose kind, key/body byte lengths and hashes; raw keys and bodies remain private and ownership verification stays false. Placement rejects any unclassified row before scratch or export creation because its owners cannot be reconciled. A new indexed store lookup returns one bounded owned kind/key and body length, releasing the SQL statement before callers run; unknown bodies are admitted before bounded allocation, while known metadata retains its original 64 MiB limit. The caller holds the existing read snapshot. Kind/key/body boundaries, malformed original bindings, exact unknown limits, known 64 MiB metadata, cursor checkpoint release, closed/WAL-only/live catalogs, full report accounting, late corruption and actual CLI diagnostic/placement cases preserve original inputs. The metadata helper does not explain the original missing-signer recovery stall. Complete ref/object/pin/index/worktree and physical source/history joins, relative or relocated owner discovery, atomic writer/path handoff and shared resource budgets remain unresolved. Family visibility does not establish full catalog, history or payload verification. External Git catalog coverage qualification passes 556 unique cases: 55 export/peer cases, all 294 ordinary store, 63 volume and 116 Git cases, 21 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions and two provisioned Btrfs identity/retained-capture cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and eight program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-git-catalog-coverage-validation-ozyro576`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native Node suites, installed artifacts and other platforms were not rerun. The public LockedDataDir startup claim is now move-only; only private reader leases share its held flock and Linux directory descriptor. Node declares its claim after every owned catalog, storage volume and reader cache, retaining exclusivity until those resources finish destruction. Saved NodeReaderConfig values and each opened NodeReader retain the same lease; their catalogs close before releasing it. A configuration can open a reader after the original Node is dropped, while a new Node remains excluded until every configuration and reader is released. The before-fix regression under `/tmp/mb-m6-ownership-lease-negative-3485uua1` confirms that the old implementation admitted a second Node while a saved writable-reader configuration still existed; its expected failure and unchanged source/driver hashes are retained. The new regression covers cloned configurations, opening after Node destruction, reader-only ownership, final release and exact stored-record reopen. This binds ownership lifetime, not atomic path/source admission: saved reader paths and later control/volume writers still need complete pinned-directory and leaf handoff. Full history/payload joins, enclosing budgets, installed artifacts and other-platform qualification remain open. The native Git source-loss fixture now shuts down and releases the original owner and its workers before normal startup acquires a new claim. It retains the same advertised QUIC endpoint, with a 30-second retry limited to address-in-use while the old transport drains. Normal P2P event-loop shutdown explicitly removes its owned direct, relay and Tor listeners before draining inbound workers, so QUIC closes its endpoint instead of continuing to accept old-address dials after the loop exits. Shutdown also disconnects peers and drains listener/connection events with a 30-second bound, allowing backpressured connection tasks to release their muxers and sockets. The existing worker-shutdown regression also verifies reuse of the released UDP port. The heavy five-node native fixture now uses four runtime workers, matching the daemon runtime and keeping synchronous catalog work from starving all QUIC drivers; the original port and phase deadlines remain unchanged. Ownership lifetime and recovery inventory source qualification passes 1231 unique cases: all 1221 ordinary workspace/all-targets cases and ten explicitly run native/foreign-UID cases. Native coverage includes Btrfs Git init/worktree/backend/retained-capture reopen, private-manifest publication and interrupted-key resume, renamed-root and bind-descendant placement, bind-file/foreign-owned locks, foreign-UID unlock-secret protection and the full native Git retained/source-loss/repeated-owner-loss recovery case with a closed-owner restart at the original QUIC endpoint. Namespace-changing cases do not overlap ordinary suites. All four debug programs build; format, strict locked workspace/all-targets Clippy, Docker lab safety and packaged acceptance-driver checks pass. Rust source, locked manifest and program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-recovery-validation-c_g8ed23`. The native owner-restart/repeated-recovery fixture also passes a separate repeat against the same source and artifact hashes, with verified cleanup and evidence under `/tmp/mb-recovery-socket-diagnostics-ld8vcx31`. This is debug-source qualification; other ignored cases, installed artifacts, the enclosing metadata budget, normal paged backup/retention/seed-recovery integration and other platforms remain open. Private storage manifests now open without following the final symlink or blocking on a FIFO, validate ownership/mode/type and the existing 64 KiB limit on the opened descriptor, and check descriptor and visible-path versions after bounded reading. Presence checks use symlink metadata, so dangling control-key and volume-manifest links are preserved as unsafe inputs. A key-only interrupted installation authenticates its existing envelope before startup lock creation or permission changes, even when control.db is absent; valid interrupted keys resume without replacement. New manifest encoding is bounded before allocation/publication. Linux publication pins the parent directory, writes and syncs an anonymous O_TMPFILE inode with mode 0600, then uses an unprivileged held descriptor through procfs to link only an absent target name. Existing files, directories, aliases and dangling links cannot be overwritten; failed writes/collisions leave no named temporary to clean up. A held parent continues to identify the original directory across reparenting. Other Unix builds use a unique private temporary and no-clobber hard-link publication; they remain unqualified. The actual before-fix daemon probe under `/tmp/mb-m6-private-manifest-before-probe-gp56s3gq` reproduces replacement of a dangling control.key link while its outside target stays absent. Anonymous publication primitives pass on workspace/tmp filesystems and provisioned Btrfs under `/tmp/mb-m6-private-manifest-anonymous-probe-dtw8jb9h`, with exact-image cleanup verified. New fixtures cover actual daemon early rejection, unsafe key-only states, valid interrupted initialization/reopen, raw names, exact/over limits, collision preservation, replaced open files and provisioned Btrfs reparenting. Source-admission/control/volume writers still require complete atomic directory handoff and external-owner reconciliation; shared enclosing budgets, complete retained conversion, installed artifacts and platform gates remain open. Private storage manifest qualification passes 547 unique cases: all 512 ordinary Node cases (including the eight local-control protocol cases), all 23 ordinary CLI process cases, three daemon startup cases and nine explicitly run native/foreign-UID cases. Native cases include Btrfs init/worktree/backend/retained-capture reopen, renamed-root and bind-descendant placement, bind-file/foreign-owned data locks, foreign-UID unlock-secret protection and Btrfs private-manifest collision/reparenting/interrupted-key resume. Namespace-changing cases finish before ordinary suites start. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 285 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-private-manifest-validation-xk0wnlec`; the post-commit audit binds the code to the commit. This is debug-source qualification; other ignored Node cases, installed artifacts and other platforms were not rerun. Linux data-directory locking now pins the directory and opens .node.lock relative to that descriptor with openat2 beneath/no-symlink/no-magic-link/no-cross-mount resolution. Existing locks must be empty regular files with one hard link, owned by the caller; the directory must also belong to the caller. Existing lock files open read-only, fresh files use exclusive creation with mode 0600 and newly created data directories/parents use mode 0700. No directory or lock permission change precedes the exclusive flock. Keyed catalog admission repeats after acquisition, then visible directory and lock identities are rechecked before and after descriptor-based permission normalization to 0700/0600; open_locked repeats admission and identity checks before opening the writable control store. Deterministic directory/lock replacement, linked/nonregular/nonempty locks and a rejected second live owner preserve original modes, identities, timestamps and bytes. A real automatic-daemon regression covers linked/nonempty locks and a live owner before socket creation. A provisioned native regression covers file bind mounts and foreign-owned files/directories. Historical original lock producers leave an empty file, so this adds no lock wire format. Unavailable safe-resolution support or unreadable ownership inputs fail closed. The checks do not make later path-based control/volume writers atomic against namespace replacement or close the remaining source-admission/lifecycle race, complete history/payload ownership joins, installed artifacts or platform gates. A before-fix actual-daemon probe reproduces both mode changes on a rejected live-owner claim, using unchanged program hashes; evidence is retained under `/tmp/mb-m6-data-lock-before-probe-1cg0cqym`. Startup-lock ownership qualification passes 541 unique cases: all 508 ordinary Node cases (including the eight local-control protocol cases), all 22 ordinary CLI process cases, three daemon startup cases and eight explicitly run native/foreign-UID cases. Native cases include Btrfs init/worktree/backend/retained-capture reopen, renamed-root and bind-descendant placement, bind-file/foreign-owned data locks and foreign-UID unlock-secret protection. Namespace-changing cases finish before ordinary suites start. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 285 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-data-lock-validation-1ofgdbb1`; the post-commit audit binds the code to the commit. This is debug-source qualification; other ignored Node cases, installed artifacts and other platforms were not rerun. Peer scratch and export placement now compare available preserved path hints in Linux filesystem coordinates as well as pathname ancestry and recorded directory identities. Binding a descendant outside its original root no longer hides it from exclusion; nested bind mounts and symlink aliases resolve to the same kernel superblock device and filesystem-relative path. Btrfs subvolume st_dev values differ from the mount-info device; original and bound subvolume paths use the latter plus the full filesystem root path, without persisting it as a native identity. The mount-table reader preserves raw bytes and the four kernel path escapes, validates normalized absolute paths, and shares native discovery's existing 256 KiB read and 4,096-byte path bounds. Non-Btrfs device mismatch, ambiguous stacked mounts and unavailable or malformed mount metadata reject placement before creation. A second bounded mount-table read rejects namespace changes during preflight. Parser/coordinate regressions cover cross-device and distinct-subvolume paths, exact/over limits, malformed escapes and ambiguity. A provisioned Linux regression covers closed/WAL-only/live control catalogs and actual nested binds of registered Btrfs subvolumes, Git history, catalog descendants and selected anchor areas; raw bytes, whitespace, symlink aliases, unchanged catalog/payload bytes and empty safe output siblings are checked. Namespace-changing native tests run before ordinary qualification jobs. This protects available hints and does not discover an unavailable relocated root or prove a recorded-identity-only descendant relation. Changes after preflight, reparenting ownership, complete history/payload joins, shared enclosing budgets and installed/platform gates remain open. Bind-mount placement qualification passes 265 unique cases: 57 export/peer cases, all 63 ordinary volume and 116 Git cases, 21 CLI process cases, retained-graph/discovery/withdrawal/graph-intent regressions and three provisioned Btrfs identity/retained-capture/bind-mount cases. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 285 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-mount-alias-validation-ntd2xe3n`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native Node suites, installed artifacts and other platforms were not rerun. Full ref/object/pin/index/worktree and stage/prune/checkout/merge/removal-intent reconciliation, receipt-to-payload/recipe/local-sector/native-pin ownership joins, pending-state reconciliation and relocated catalog/volume discovery remain open. Complete mount-subdirectory alias and concurrent reparenting/ownership qualification remain open. Linux Node/Git catalog admission and Git discovery listing now use the non-creating snapshot reader. WAL-only catalogs use SQLite’s private index with validated headers and unchanged main/WAL versions and sidecar absence; empty WALs and interrupted tails remain compatible with native restart. Catalog read operations reuse an enclosing read-only transaction without ending it; this corrects nested metadata reads exposed by native admission qualification. Admission/WAL source qualification passes 961 unique cases: 474 Node, 288 store, 102 Git and 19 CLI ordinary tests; all 64 provisioned Git cases, 11 native Node cases, extent sharing/prune, stock-Git bridge and raw Unix paths. All four debug programs build; format, strict locked workspace/all-targets Clippy, unchanged 284-source/ten-binary hashes and native cleanup are verified. The packed-checkpoint case exceeded an initial 900-second harness cap; its separate failed-attempt evidence is retained, and unfinished checks pass on the same frozen inputs with a 2,400-second outer cap and unchanged application phase deadlines. Eleven Node, 26 store and two CLI process fixtures and installed-artifact qualification remain open. Linux library `Node::open` now checks the preserved catalog before directory/lock creation or permission changes and rechecks after locking. A nine-combination key/journal regression verifies unchanged directory identity/mode/timestamps, catalog/key/journal bytes and file sets, and no new lock file. Early Node admission qualification passes 38 unique cases (12 source-policy, 1 single-data-owner, 1 discovery-maintenance, 20 ordinary-process, plus four provisioned native Git/backend/capture reopen cases). All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source files and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-early-admission-validation-u30_afvh`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. Automatic daemon unlock now reads and verifies the configured seed before this preflight and lock/socket setup; a real-process regression covers closed/WAL-only/live-WAL catalogs and wrong identities. Linux manual daemon unlock now waits for the seed identity and read-only catalog admission before directory permission changes or data-lock creation. Its control listener uses a process-lifetime abstract Unix address derived from the configured socket location and UID; the existing CLI socket argument still finds it without creating parents, replacing a saved control-path file or cleaning it on shutdown. Server and client both verify peer UID; clients reject a foreign owner before sending the unlock secret. The raw data-lock helper is crate-internal, so public callers acquire a lock through `Node::lock_data_dir_with_seed`; `open_locked` still repeats admission. Wrong identities and withdrawn catalogs leave the manual daemon locked and retryable. Closed/WAL-only/live catalogs, absent/file/missing-parent control paths and repeated rejected unlocks preserve original directory identity/mode/timestamps, file sets and catalog/key/journal bytes, with no new lock or socket. Actual manual native unlock, network/Tor startup retry and SIGTERM cleanup regressions remain in the process suite. Abstract listener exclusivity/release, aliases and saved control files have direct protocol tests; a privileged foreign-UID server checks zero received secret bytes. Manual daemon admission qualification passes 51 unique cases: 12 source-policy, 8 control protocol, 3 daemon startup and 21 CLI process cases, single-owner/discovery regressions, four provisioned Btrfs reopen/backend/capture cases and a privileged foreign-UID control server. All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source-file and seven program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-manual-admission-validation-3r5sj2py`; the post-commit audit binds the code to the commit. This is focused debug-source qualification; complete ordinary/native suites, installed artifacts and other platforms were not rerun. Rollback/partial-journal recovery, atomic writer handoff and shared WAL-index resource budgets remain open. Catalog export payload and explicit preserved parity readers now reuse non-creating connections without an export-wide explicit read transaction. Checkpoint/transcript recovery now fetches one owned bounded row per indexed key lookup, releasing its SQL cursor before peer callbacks. Input guards run before each lookup and after callbacks, rejecting live changes without an unbounded appended-row scan. Cursor qualification passes 63 unique cases (38 legacy-export, 1 large-retained-graph, 2 legacy-discovery, 19 ordinary-process, 1 capture-withdrawal, 1 graph-intent-compatibility, and one provisioned Btrfs renamed-root case). All four debug programs build; format and strict locked workspace/all-targets Clippy pass. All 284 source files and six program/test-driver hashes remain unchanged, and native mount/loop/image cleanup is verified. Evidence and the distinct passing-case inventory are retained under `/tmp/mb-m6-recovery-cursor-validation-h6i65pwl`; the post-commit audit binds the code to the commit. This is a focused debug-source qualification; complete ordinary/native suites and installed artifacts were not rerun. Local signed-revision selection uses a short snapshot, and input-version guards run before staging and publication; fixed/variable parity loads also check before/after reads. Changed inputs reject publication and clean owned staging through the pinned parent. Export/parity source qualification passes 966 unique cases: 477 ordinary Node, 290 store, 102 Git and 19 CLI process tests, all 64 provisioned Git cases, 11 native Node cases, extent sharing/prune, stock-Git bridge and raw Unix paths. All four debug programs build; format, strict locked workspace/all-targets Clippy, unchanged 284-source/ten-binary hashes and native cleanup are verified. Eleven Node, 26 store and two CLI process fixtures, installed artifacts, atomic writer/path/ownership handoff, complete key-manifest/external-owner reconciliation, other-platform reader checks and common resource budgets remain open. Shared validation now streams placement records independently of report construction, retaining only candidate ancestry and one hint. A 219-capture/28,032-pin fixture exceeds the 32 MiB report limit while placement succeeds; late unsafe/corrupt records and parent replacement reject before client creation. Its 46 source/process/discovery/Btrfs checks, all four program builds, format and strict workspace Clippy pass with fixture cleanup verified. External Git catalogs/refs/pins/worktrees and other intents, recipe/pin/volume owners and unresolved relocation/path races and unavailable mount hints, other reader no-creation qualification, incomplete-journal recovery, retained conversion and upgrade/source-loss gates remain open. |
| R2 — Git and backup capacity consistency | Replace the separate 64 MiB Git graph and 32 MiB serialized-backup assumptions with one end-to-end budget, or versioned bounded metadata chunking. Count refs, tree/commit/tag bytes, blob recipes, surrounding private metadata, and checkpoint/transport constraints. Preflight graph-changing operations before publishing refs, index state, or a protection claim. | Just-below/above boundary tests for commit, fetch, merge, tags and pins; rejected operations leave visible state intact; accepted graphs serialize, back up, and recover with exact bytes and IDs. Reopen and retry preserve the same decision. |
| R3 — snapshot scale | Treat 39,488 data-sector references at 64 KiB (about 2.41 GiB of full sectors) as the current v1 bound. Define supported production dataset/history sizes beyond this prototype ceiling, then implement versioned authenticated paged/chunked catalogs or another explicit scalable design with bounded traversal. Keep early diagnostics for the current bound until migration is available; do not merely raise constants. | Dense, sparse, hard-linked, many-small-file, and multi-revision/Git-history cases above the old ceiling and at the declared limit; just-over-limit rejection before publication; bounded memory, encoding and recovery; old-format migration and seed-only restore after any format change. |
| R4 — complete volume evacuation (completed, including historical uploaded information) | Durable variable READY transfers preserve attempt/receipt/verification evidence, verify destination bytes before publishing its location, and conditionally withdraw the source. GC/abort cancellation, offline cleanup ownership, pending upload completion, and per-source durable retirement are implemented alongside legacy migration. Fresh information activation retains original transcript evidence. Normal evacuation upgrades legacy empty information markers only after exact original signed-witness, historical indexed-roster and physical-byte authentication under control/volume writers; unavailable or damaged evidence preserves the source. | Historical transfer qualification remains recorded below. Current qualification: 276 ordinary store tests and 82 selected Node authority/volume/upload/evacuation tests pass; ignored cases remain excluded. Disposable Btrfs separately passes headroom and all three information/parity/legacy custody lifecycles, including real source removal, repair, shared owners and reopen, with cleanup verified. Formatting and strict workspace/all-targets Clippy pass. Exact release-artifact/native/platform qualification remains R7. |
| R5 — backup/signature progress | Keep the existing relay-only recovered-peer/missing-signer issue open. Correlate each job, event, signer, proposal lock, and selected connection; diagnose remaining response and catch-up paths. Preserve verified partial signatures through retry/reopen and provide bounded waits with actionable blocked status. Lifecycle and coding Add clients reject cryptographically invalid replies before durable collection, so one invalid member cannot cancel a reachable valid quorum. Signature RPCs now retain each attempt’s selected connection/session/path/remote address and signed routing-record source/sequence/hash, correlated by wire request ID through signer admission/lock workers. | Three new diagnostic regressions cover endpoint replacement/direct-to-relay retry, an undispatched deadline and real QUIC admission correlation; 46 affected transport, quorum, worker and reopen regressions also pass. Four invalid-signer regressions cover majority and unanimous progress/one-signer retry in both paths; both majority cases reproduce the prior abort. Those cases plus existing slow-minority, partial-signature reopen and administration fixtures pass. This is not a causal explanation of the old stall. Repeated exact-source provisioned topology runs with stale endpoints, relay-only recovery, lagging signers, partition/heal and restarts remain required. |
| R6 — ordinary Git runtime dependency (completed) | Default Nix programs now include pinned stock Git through runtime wrappers; the optional alias uses that runtime. Standalone binaries declare their Git PATH requirement and discovery reports a missing dependency clearly. | Installed runtime/alias passed packed import and both bridge directions with exact bytes/IDs in isolated environments, with and without the alias. Raw standalone missing-Git failure left visible refs/history and working bytes unchanged. A dedicated CI job repeats the gate. Broader artifact qualification remains R7. |
| R7 — release validation | Preserve existing CI jobs for formatting, Clippy, locked tests, reflink/topology, port mapping, and private Tor. Add the complete provisioned `git-linux-acceptance.sh` gate and qualification of the actual packaged binaries and runtime dependencies. The packaged job selects all four installed programs and freezes process drivers through `packaged-process-acceptance.py`, recording source/wrapper/payload/driver hashes, positive test counts and topology cleanup; caller cleanup separately verifies mount/loop/image removal. | The installed musl runtime/alias and mandatory runner on `d80c108` pass three isolated-PATH Git packaging scenarios and 27 distinct process cases in 28 executions: 23 ordinary, raw paths, the stock-Git bridge, five-daemon topology/seed recovery (774.93 seconds), and two fresh relay-signer partition/coordinator-crash runs (711.91 and 742.50 seconds). Both bounded original-signature proofs have distinct request IDs and verify the same event/attempt with all five original signers before commit. Independent audits verify the 320-file immutable Nix source, candidate/alias/drivers and live installed daemon identities, plus filesystem/network cleanup after both attempts and final removal. All 23 earlier workspace binary hashes and identical Rust/dependency inputs remain qualified. Earlier installed candidates stay rooted. This qualifies the listed Linux slice; the full native/upgrade/multi-volume/private-Tor/platform matrix, R5 historical causal diagnosis and complete fault matrix, enclosing admission/normal paged recovery and user-deferred dense capacity/native platform gates remain open. Nix build-only checks cannot stand in for these tests; unsupported privileged environments cannot silently count as passes. |

The coding directory builder now has explicit full original-witness construction
credits and a declared group-count fence. The actual single-owner geometry
reserves 269 forests and 4,958,102,421,504 encoded page bytes; compact-only
measurements do not establish this upper bound. Frozen qualification passes
1,397 distinct tests, including both native recovery fixtures and the large
atomic writer, with 331 inputs and 23 exact executables audited. Exact
superseded-inode retirement reclaims 9.94 GiB; target uses 47.42
GiB. These construction credits do not close the complete enclosing resource
policy or normal paged recovery gates. See ADR 0002 and `/tmp/mb-m6-full-witness-capacity-final-k91to5f7`.

Automatic packing construction now shards complete sources and sectors while
preserving original identities and global indices. One declared reservation
combines complete compact packing with full original-witness coding before
staging; the required geometry has an upper reservation of 4,631,391,975,828
stream/envelope bytes and 4,979,121,455,104 encoded page bytes. Frozen workspace,
bulk-writer and native recovery qualification passes 1,404 distinct tests on
335 inputs and 23 exact executables. Retirement reclaims 9.67 GiB;
target uses 47.43 GiB. This constructs both directories and passes their
existing joins; complete enclosing policy, bounded incremental updates and
normal producers/retention/seed recovery remain open. See ADR 0002 and
`/tmp/mb-m6-packing-coding-production-a6kytmjm`.

Published paged revision metadata now has explicit version-one global,
dataset and guild occurrence quotas. Repeated source/private roots consume
revision/byte/page/record credits even when physical pages and data are shared.
Bounded adoption/abort resumes at startup; publication/cancellation guard exact
original identities and all scoped totals through the enclosing writer. Both
native fixtures cover configuration or existing adoption, shared successors
and source loss. Frozen qualification passes 1,413 distinct tests on 337 inputs
and 23 executables; retirement reclaims 10.64 GiB and leaves 47.43
GiB in target. These are published exposure limits; complete structural,
pending capture/checkpoint/replay/SQL/WAL/scratch/physical policy and normal
paged recovery remain open. See ADR 0002 and `/tmp/mb-m6-published-revision-quota-j49ro9os`.

Control/parity stores now support persistent logical SQL database-page limits,
including schema/index and freelist pages. Existing/cached writers refresh the
pager cap under their data triggers; exact policy/guard and bounded schema
checks preserve atomic refusal/rollback. Node control/volume configuration,
read-only/reopen, both native retained/source-loss fixtures and the large atomic
writer are qualified. Frozen qualification passes 1,420 distinct tests on 339
inputs and 23 executables; retirement reclaims 10.65 GiB and leaves
47.44 GiB in target. WAL/checkpoint tails, scratch, physical reservation,
complete enclosing policy and normal paged recovery remain open. See ADR 0002
and `/tmp/mb-m6-database-page-quota-zeo6a1k8`.

Control/parity stores now admit explicitly declared durable WAL/rollback-
journal byte ceilings through native I/O, including inherited bytes and commit-
time exhaustion. Exact policy/guard readback, cached writers, directory/native
locks, admitted shell writes and atomic parity BLOB/progress publication are
qualified. Nine Store and one Node regressions, both native retained/source-
loss fixtures and the >512 MiB atomic writer pass. Frozen qualification passes
1,430 distinct tests on 342 inputs and 23 executables; retirement reclaims
10.65 GiB and leaves 47.44 GiB in target. Complete workload/retention/
physical reservation, aggregate/copy/scratch policy and normal paged recovery
remain open. See ADR 0002 and `/tmp/mb-m6-journal-quota-cfu06vgl`.

A guarded local catalog capacity contract now composes retained unique data,
private/bootstrap and original legacy sources, source-tree/revision occurrences,
authority, packing, full original coding witnesses and independent proof/history
replay. Scoped ledgers, final publication/reservation guards, both checkpoint
custody layouts and Node startup/configuration enforce it. Six Core, eight Store
and two Node regressions and frozen full qualification pass 1,446 distinct tests
on 346 inputs and 23 executables. Retirement reclaims 11.82 GiB and leaves
47.44 GiB in target. Full workload/physical admission, existing-catalog
adoption, normal paged recovery and R5/R7 remain open. See ADR 0002 and `/tmp/mb-m6-dataset-policy-rcjnf3px`.

Native anchors now produce private paged namespace/recipe roots directly,
with complete construction geometry admission before source I/O/callbacks,
128-reference fragments, sparse/hard-link joins and original capacity guards.
Five ordinary regressions and a provisioned native capture/paged publication/
reopen/restore fixture preserve exact bytes and heads without a flat revision.
Frozen full qualification passes 1,452 tests on 348 inputs and 23 executables;
retirement reclaims 10.46 GiB and leaves 47.44 GiB in target.
Complete producer ownership/preflight, ordinary/Git production, enclosing
physical/distributed activation, retention/seed recovery and R5/R7 remain open.
See ADR 0002 and `/tmp/mb-m6-native-producer-yt6u5_c5`.

The Node native paged candidate API now owns capture, bounded source ordering,
admission and atomic local publication through retry/reopen and source loss.
Final operation ownership and all catalog/source/quota writes commit together,
with independent current writer/member and original registration/backend/
ancestor guards after the last writes. Cancellation and cleanup preserve shared
pins and retire one record per step. Recovery inventory/startup recognize the
owner journal. Three Store and one ordinary Node regressions and the complete
provisioned native candidate lifecycle pass; frozen full qualification passes
1,457 tests on 350 inputs and 23 executables. Retirement reclaims 11.74 GiB
and leaves 47.47 GiB in target. Full workload/physical/pending-job admission,
ordinary/Git production, distributed activation, normal retention/seed recovery,
legacy consumers and R5/R7 remain open. See ADR 0002 and `/tmp/mb-m6-native-owner-z1hqnvv_`.

Source-authorized fresh packing now streams complete source proofs and original
packed payloads/descriptors through an indexed encrypted disk allocator. Owner
rounds, spare slots, virtual-zero mappings, exact bytes and original IDs match
the existing allocator. Construction and source-authority credits are paid
before callbacks; failed batches roll back, and complete emitted-page/coverage
EOFs are required before placements or candidates can be used. Frozen full
qualification passes 1,464 tests on 353 inputs and 23 executables. Retirement
reclaims 9.83 GiB; target uses 47.48 GiB. Durable enclosing operation
ownership, incremental edits, full physical/pending-job admission, paged-base
authority, distributed activation and normal backup/retention/seed recovery
remain open. See ADR 0002 and `/tmp/mb-m6-packing-producer-6w61ltjm`.

Packing authority now imports both completed paged checkpoint layouts from an
independently trusted original state hash and full quorum/body/source/history
proof. Typed bounded facts preserve source commitments, members/latest fences,
revision parents, tombstones and globally reserved retired IDs; candidate rows
start empty. Enclosing credits survive across source trees and subsequent
candidate/evidence admission. Both layouts feed the actual paged packing
producer; original legacy retirement and real paged predecessor pruning are
qualified. Frozen full qualification passes 1,471 tests on 356 inputs and 23
executables. Retirement reclaims 9.63 GiB; target uses 47.48 GiB.
Durable packing source custody, incremental edits, complete policy/quotas,
distributed activation, normal backup/retention/seed recovery, legacy consumers
and R5/R7 remain open. See ADR 0002 and `/tmp/mb-m6-paged-packing-base-nht7o9z5`.

Pending packing jobs can now retain exact published paged source custody with
immutable operation/base/budget, original private authentication and current
base/event guards. Bidirectional loans and checked owner counts preserve
bundle/bootstrap/native serving and exclude cancellation through reopen and
bounded retirement; verified equivalent source replacement remains available.
Eight lifetime/rollback regressions and 1,479 full qualification tests pass on
358 inputs and 23 executables. Retirement reclaims 19.06 GiB; target uses
48.58 GiB. Durable Node packing/coding and checkpoint ownership handoff,
complete quotas/admission, normal backup/retention/seed recovery and remaining
software gates stay open. See ADR 0002 and `/tmp/mb-m6-packing-source-custody-fgsiuzee`.

Closed packing-source loans can now hand exact private catalog custody to the
immediate successor checkpoint atomically in both public layouts. Original
quorum/history, actual base/events, destination admission and local private
authentication guard acquisition before source release; exact retries keep
the same destination owner. Node borrowing and the real Linux capture/reopen
fixture preserve source serving and reject cancellation while borrowed. Eight
new transfer cases, eight existing loan cases and 1,487 full qualification tests
pass on 359 inputs and 23 executables. Retirement reclaims 10.72 GiB;
target uses 48.59 GiB. Durable packing/coding output custody, complete
quotas/admission, distributed availability/activation, normal backup/retention/
seed recovery and R5/R7 remain open. Normal producers stay disabled; the user
defers real dense 1 TiB and native Windows/macOS hardware qualification until
the tool and other software items are ready. See ADR 0002 and `/tmp/mb-m6-packing-checkpoint-handoff-7zoqtutr`.

Pending packing payload loans now preserve exact original physical attempts and
locators through partial upload, STAGED/READY custody, shared ownership, reopen,
offline copies and bounded release. Node checks indexed current authority,
actual base, CAPP/scoped admission and original physical bindings; completed
bytes authenticate in one bounded incremental-blob pass. Eight Store and four
real-volume cases,
maximum 4 MiB/final-role coverage and the extended native fixture pass. Full
qualification passes 1,499 tests on 362 inputs and 23 executables; retirement
reclaims 11.80 GiB and target uses 48.59 GiB. Complete durable producer/page/
source/output-proof integration, aggregate quotas, indexed volume cleanup,
availability/activation, normal backup/retention/seed recovery and R5/R7 stay
open. Producers stay disabled; hardware runs remain user-deferred. See ADR 0002
and `/tmp/mb-m6-packing-output-custody-h2mugql5`.

The latest complete-source prerequisite passed on `30cff18`, including ordinary
Node/Store and the provisioned native cases recorded under R7. Its subsequent
packaged musl build failed; `faeb44d` corrects the ioctl argument typing, with
focused physical-I/O qualification only. Correct R3-NATIVE-RECORD-QUOTA-RESTART
and R5-VIRTUAL-ZERO-ROUTING, then qualify the merged source and corrected packaged
musl build before installed runtime gates. The reproduced first-verifier routing
omission and restored-wait fixture starvation have corrections; keep the original
initial-coverage evidence, 900-second native timeout, later Store runner timeout
and historical relay-only stall separate. These fixes and later positives
establish no common cause or complete R5 closure.

Explicit Store/Node birth, same-host process restart, ordinary managed opens/
readers and additional native volume creation are now implemented. Complete
CLI/default policy selection, managed rekey, host-reboot behavior and quiescent
existing/restore/host-relocation adoption. Integrate complete shared reservations
for ownership bookkeeping, SQL/WAL/SHM/temporary, scratch, payload and checkpoint
copies across normal operations and volumes. Current process-local native
physical pools and traversal/scratch ledgers are increments toward
R3-SINGLE-OWNER-METADATA, not complete single-owner 1 TiB admission.
Continue the remaining R1 safe-upgrade/recovery contract. Finish distributed
availability/current activation, checkpoint ownership joins and normal paged
capture/packing/checkpoint/retention/seed-only recovery under the complete policy
before enabling producers or claiming retained-capacity completion. R5 diagnosis
and R7 release qualification continue alongside this integration. R4 evacuation
and R6 packaging are complete; preserve their regressions. Complete all applicable
corrections before Milestone 7 compatibility freeze. Native Windows/macOS work
remains in the roadmap; a narrower production platform scope requires an explicit
product decision rather than treating missing platform support as complete.

On 2026-10-10 the user deferred the real dense 1 TiB recovery run and native
Windows/macOS qualification until the tool and other items are ready and
external test resources are available. Continue implementation and local
qualification. Keep those acceptance gates open; the required retained capacity
and supported-platform scope have not changed.

The installed Linux runtime and Git alias from committed `c4efb51` pass a fresh
Nix musl build and two complete runs of the current packaged process matrix.
Each run passes three isolated-PATH Git packaging scenarios and 26 distinct
process cases: 23 ordinary, raw Unix paths, stock-Git bridging and five-daemon
topology/seed recovery. The topology runs complete in 679.73 and 597.27 seconds.
Five live daemon payloads per run match the installed candidate; independent
audits verify identical source/wrappers/payloads/drivers, eight private archived
peer logs per run and filesystem/network/forwarding cleanup. Evidence is in
`/tmp/mb-m6-installed-c4efb51-1_ha0nbo` and
`/tmp/mb-m6-installed-repeat-c4efb51-m3pnuksl`. Observed incomplete signature
groups complete in the retained logs, with longest intervals of 116.76 and
103.39 seconds. This qualifies the listed current Linux artifact slice; the
historical R5 cause and partition/interrupted-retry matrix, remaining R7 native/
upgrade/multi-volume/private-Tor gates and deferred capacity/platform gates
remain open.

The page store now has an explicit encoded-page quota and immutable per-intent
reservations shared across writer connections. Page staging, root/bundle
publication, cancellation and actual GC update the ledger in their existing
transactions. Shared pages stay charged until physically collected. The frozen
qualification passes 509 distinct core/store/paged Node/native cases, formatting,
strict locked workspace/all-targets Clippy, all-target test compilation and four
debug program builds, with source/binary hashes and native cleanup verified.
Configured quota lifecycle is covered in store fixtures; the native migration
regression retains its existing unconfigured behavior. The enclosing policy
still needs SQL/WAL and payload headroom,
traversal work, dataset/history and guild quotas before normal paged producers
can be admitted; generation-floor retirement also remains open.

The encoded-page writer now also enforces one limit per dataset and one
aggregate limit per guild, including private/source dataset pages and public
guild pages. Original reservation identities and all three ledgers change
atomically through staging, publication, cancellation and actual final-owner GC.
Shared/cancelled/unpublished pages remain charged until collection. Initial
enablement validates bounded original pages and loans and reconciles exact store
totals without rewriting original rows; corrupt/orphan records and suppressed
SQL writes reject atomically. Policy resizing is grow-only and scan-free.
Eight new Store fixtures and both configured/adopted Btrfs native recovery
variants pass. Fresh frozen qualification runs the complete ordinary workspace
and both native cases: 1,359 distinct tests in 1,367 positive executions,
formatting, strict locked workspace/all-targets Clippy, all-target compilation
and four debug programs. All 322 source files and 23 executable paths stay
unchanged during the run; the documentation update follows. Native cleanup,
archived qualification artifacts, auxiliary work and installed roots are
verified. Cache cleanup reclaims 8.94 GiB, with qualified binaries unchanged.
Evidence is in `/tmp/mb-m6-scoped-page-quota-validation-on4iksql`.
Other 121 ignored cases and fresh installed artifacts were not run for this
change. Sparse logical 1 TiB is distinct from dense qualification. Enclosing
SQL/WAL/index/record/payload/scratch/traversal policy, normal paged production/
retention/seed recovery and generation-floor retirement remain required;
dense 1 TiB and native Windows/macOS qualification remain user-deferred.

Normal variable repair, retained recovery staging and activation now use the
completed durable original-history index instead of materializing legacy
coding vectors. Lookups match the original signed transcript hash, descriptor
and historical membership under genesis/current-tip/history fences. Retired
groups remain available until Forget; a new Add keeps the group identity and
binds its new witness. Group/event evidence readers bound transcript SQL
allocation and decoding to 600 KiB and original Add events to 128 KiB.
Event-witness fallback and local historical Add attestation consume the same
authority; evidence serving remains available before Add and after Forget.
Absent/incomplete indexes preserve the independently fenced legacy
compatibility path; damaged completed group/evidence rows reject.

Four new Node fixtures cover real recovery staging/activation after reopen
with unusable flat state, live/retired custody, Forget/re-add, substituted
valid aliases, missing/corrupt/oversized records, final batch fences and
legacy catch-up. Frozen qualification passes the complete ordinary
workspace/all-target inventory and both provisioned Btrfs recovery cases:
1,363 distinct tests in 1,367 positive executions, including 194 Core, 394
Store, 117 Git and 534 Node. Formatting, strict locked workspace/all-targets
Clippy, all-target compilation and four debug program builds pass. An initial
extra parallel-target run and an overlapping diagnostic hit the offline-spare
fixture's unchanged 90-second deadline. The previous/current binaries pass the
isolated case in 52.13/48.76s; the complete Node target then passes with its
four threads and no other target executing. All failed logs are retained, with
no source or timeout change. All 322 source files and 23 executable paths stay
unchanged during qualification; documentation updates follow the run. Native
cleanup, installed roots and all 14 auxiliary uncommitted files are verified.
The current candidate supersedes the ce06a7b debug archive. Retiring only that
archive reclaims 9.85 GiB and leaves 47.24 GiB in target. Current qualified
executables, earlier binaries supporting installed qualification, original
records and hash inventories remain available. Evidence is retained under
`/tmp/mb-m6-bounded-coding-lookup-kcyguyl7`.

Other 121 ignored cases remain unexecuted; installed artifacts were not
rebuilt for this change. Btrfs uses sparse logical 1 TiB, without dense
qualification. This completes these coding point consumers, not bulk lifecycle
indexing, complete paged checkpoint authority/custody/activation, enclosing
admission or normal paged capture/packing/retention/seed production. Fixed
legacy-group migration and the remaining R1/R2/R3/R5/R7 gates stay open. Dense
1 TiB and native Windows/macOS qualification remain user-deferred.

Retained legacy migration now connects to configured page quotas. Its
authenticated dry run counts native and optional Git pages and bounds source
tree geometry before atomically reserving all three or six roles and writing
the immutable migration journal. Late-role or journal failures roll back every
prefix; interrupted admitted jobs remain resumable, and cancellation fences
unreached/pre-quota roles without acquiring credits. Frozen qualification passes
514 distinct core/store/Node/native cases, including configured shared migration
and final-owner GC for legacy formats 1/3/4/5 and real Btrfs capture/recovery.
Formatting, strict locked workspace/all-targets Clippy, all-target compilation,
four debug program builds, source/binary hashes and native cleanup pass.
Evidence is retained in `/tmp/mb-m6-page-admission-validation-lqep397s`.
This connects the encoded-page limit to retained migration; enclosing logical
data/payload headroom, SQL/WAL, traversal, dataset/history/guild policy, normal
producers and verified generation-floor retirement remain open.

Retained-source quotas now account for unique retained authenticated data
sources independently in each dataset. Original migration admission reserved a
conservative original-source bound in the same writer as its page roles and journal;
publication converts only newly retained identities and returns unused credits.
Shared sources remain charged until their last retained binding is cleaned up,
including cancelled owners, while source-location repair leaves accounting
unchanged. This counts non-hole source logical bytes and source cardinality;
sparse lengths, aliases, private/bootstrap metadata and physical payload/parity
still need enclosing policy. The guild logical-source increment is recorded
below. The follow-up below adds durable
dependency ownership across the admission/publication interval.
Initial enablement over existing paged bindings requires bounded
adoption and currently rejects before mutation. Frozen qualification passes
518 distinct core/store/Node/native cases, including legacy formats 1/3/4/5,
joint data/page/journal rollback, interrupted publication, final shared-owner
cleanup and quota-enabled Btrfs capture/recovery with repeated source IDs and
checked repair. Formatting, strict locked workspace/all-targets Clippy,
all-target compilation, four debug program builds, source/seven-binary hashes
and native cleanup pass. Evidence is retained under
`/tmp/mb-m6-retained-source-validation-za4kq3hy`. These tests qualify this local
quota increment; normal consumers and the enclosing admission, history,
generation-floor, installed-artifact/platform/topology and retained 1 TiB
gates remain open.

Incremental retained migration now authenticates and deduplicates original data
before admission, reserves only new identities, and durably holds shared source
charges and physical native anchors in the same transaction as page roles and
the migration journal. Shared sources therefore need no temporary duplicate
data capacity, and original-owner cleanup cannot invalidate admission. A
repeatable sorted iterator keeps the store API bounded per record; immutable
input digests fence changed retries. Publication transfers holds to authenticated
data bindings atomically. Cancellation releases one hold per cleanup step,
including admitted operations that never published. Existing conservative
reservations retain their original capacities and acquire the same shared
dependency holds during authenticated resume. A retained-fact accessor requires
the bundle-selected Verified/Cancelled state without enabling serving of a
cancelled revision. Six store fixtures cover the ownership/cleanup races,
reopening, competing connections, immutable replay, old reservations and SQL
rollback; the cancelled-binding case fails before the correction. Legacy
formats 1/3/4/5 and native capture/recovery now repeat migration at the exact
unique data-byte/source limit. Frozen qualification passes 530 distinct
core/store/paged Node/native cases, formatting, strict locked workspace/all-
targets Clippy, all-target compilation and four debug builds. Source, seven
binaries and 21 embedded protocol/helper inputs match; native cleanup is
verified. Evidence is in
`/tmp/mb-m6-source-dependencies-validation-kw33d3cx`.
This closes incremental source admission for explicit retained
migration. Full enclosing metadata/payload/SQL/WAL policy, normal producers,
bounded adoption, generation floors and the deferred capacity/platform gates
remain open.

Retained logical source admission now also enforces an explicit aggregate limit
per guild across dataset/owner boundaries. Its byte/source/job counters change
inside the existing page/source/journal writer; repeated revisions and dependency
holds preserve one dataset charge until actual final-owner cleanup. Activation
streams existing accounted dataset ledgers with bounded row allocation in the
immediate writer, including stored cancelled sources and outstanding credits,
and rejects over-limit adoption atomically. Immutable replay, independent guilds,
grow-only policy changes and read-only/reopen behavior are preserved; malformed
or missing accounting cannot reset admission. Six new regressions and the native
Btrfs shared-migration/source-loss/interrupted-repair fixture pass with both
limits enabled. Frozen qualification passes 544 distinct cases: 178 core,
329 ordinary store, 35 paged Node, the certified-writer migration case and
provisioned native recovery. Formatting, strict locked workspace/all-targets
Clippy, all-target test compilation and four debug builds pass. Source, seven
binaries and 21 embedded protocol/helper inputs match, and native cleanup is
verified. Evidence is in `/tmp/mb-m6-guild-source-validation-if3dgpyt`.
Incremental-cache cleanup reclaims about 7.5 GiB with qualified binaries unchanged.
This is the logical
data-source limit; private/bootstrap metadata, physical payload/coding, SQL/WAL,
traversal, previously unaccounted paged-data adoption and normal producers still
require the complete enclosing policy and deferred capacity/platform gates.

Retained public authority now has an explicitly budgeted format two, selected
by draft paged checkpoint format nine. Each original tree stays bounded, while
the enclosing proof pays for every retained source/body occurrence and admits
source-frame debt before exposing nested references. Original formats, signed
bytes and root identities remain unchanged. Complete public joins and the
guarded paged owner carry that same budget through original-history proof,
quorum binding, reopen and bounded cancellation. Frozen local qualification
passes 524 distinct core/store/paged Node/native cases, formatting, strict
workspace/all-targets Clippy, all-target compilation and four debug builds.
Source, seven binaries and 21 embedded protocol/helper inputs match; native
cleanup is verified. Evidence is in
`/tmp/mb-m6-history-admission-validation-zjwq8pri`.
Full private/payload/SQL headroom, dataset/guild admission, normal
producers and the deferred real retained-capacity gate remain open.

Local data recipes now have version-three owner bindings, bounded by 256 bytes,
with one shared scoped/source/anchor/recipe identity for identical opaque bytes.
The dictionary retains exact owner backlinks until actual final-owner cleanup;
each owner keeps an independent repair generation and may transfer to a new
recipe/anchor without changing another owner's view. Old inline versions one
and two remain readable and replay without rewriting their original bytes.
Publication, replacement and cancellation cleanup change recipe references and
physical pins in the same writer. Missing dependencies, counter/backlink
disagreement, ignored/reverted SQL writes and malformed lengths fail closed.
Four local fixtures cover 32 small signed catalogs with real 8 KiB recipe
sharing, independent repairs, original replay, reopen/cancellation and SQL
faults. Encoded-value arithmetic for 32 dense 1 TiB references replaces a 4 TiB
repeated recipe bound with less than 512 GiB of shared recipe and owner values;
this excludes SQL keys/indexes/WAL, native validation, capture manifests,
packing/coding and payload. Frozen qualification passes 534 distinct core/store/
paged Node/native cases, formatting, strict locked workspace/all-targets Clippy,
all-target compilation and four debug builds under Cargo/rustc 1.99.0. Source,
seven binaries and 21 embedded protocol/helper inputs match; native cleanup is
verified. Evidence is in `/tmp/mb-m6-shared-recipes-validation-bcp0vuql`. Full
metadata admission and the normal paged pipeline remain open.

The local packing join now has descriptor format two with a separately supplied
trusted byte/page/record budget. Each original descriptor/source stream retains
its individual limits; format one and the original unbudgeted APIs retain their
combined ceiling. Certified source authority is debited before either stream is
fetched, and the completed index retains its admitted remaining budget. Coding
directory and public checkpoint joins fund their complete authority/packing/
coding work without resetting debt at a section boundary. Four new regressions
and existing guarded checkpoint ownership fixtures exercise the budgeted path.
Frozen qualification passes 538 distinct core/store/paged Node/native cases,
formatting, strict locked workspace/all-targets Clippy, all-target compilation
and four debug builds under Cargo/rustc 1.99.0. Source, seven binaries and 21
embedded protocol/helper inputs match; native cleanup is verified. Evidence is
in `/tmp/mb-m6-packing-admission-validation-zcytodje`. Cache cleanup reclaims
about 7.6 GiB with qualified binaries preserved. This removes a local aggregate
admission bottleneck;
the complete section/dataset/guild policy, private/payload/SQL headroom, normal
producers and deferred capacity/platform acceptance gates remain open.

Original packing streams now have an explicitly budgeted sharded directory.
Bounded ordered source ranges and contiguous global descriptor ranges preserve
original sector IDs and indices. One active reader completes all nested and
directory EOFs; one disposable scratch transaction carries authority,
uniqueness, coverage and Merkle joins across boundaries. Interior padding-only
parts are valid, but the global last sector must contain a source. Eleven new
core/Store regressions pass. The declared retained geometry represents
48,777,248 sources and 65,036,331 sectors with four bounded root records; it
neither materializes those streams nor qualifies dense storage/recovery.
Frozen qualification passes 555 distinct cases: 185 core, 333 ordinary Store,
35 paged Node, the certified-writer migration case and provisioned Btrfs native
recovery. Formatting, strict locked workspace/all-targets Clippy, all-target
test compilation and four debug builds pass. Source, seven binaries and 21
embedded inputs match, and native cleanup is verified. Evidence is retained in
`/tmp/mb-m6-packing-shards-validation-newgl31k`. Cache cleanup reclaims
8.61 GiB with qualified binary hashes preserved. Transitive part ownership,
certified authority/coding/checkpoint integration, complete enclosing metadata
and physical policy, normal producers/recovery and deferred capacity/platform
gates remain open; see ADR 0002.

Sharded packing now joins the coding directory under one trusted budget with
source-authority debt preserved through both boundaries. The certified legacy
source bridge retains its trusted base, exact commitments/cardinality and signed
candidate cursor; complete coding coverage and bounded witness replay use the
original checks in the same private scratch index. A durable combined owner
pins both directories and every nested source/descriptor/forest root before
traversal, publishes only after all local EOFs, resumes immutable interrupted
jobs and releases one cancelled root closure per transaction. Shared owners
preserve referenced parts after staging owners retire and through reopen.
Eleven new regressions pass. Frozen qualification passes 566 distinct cases:
186 core, 343 ordinary Store, 35 paged Node, the certified-writer migration case
and provisioned Btrfs native recovery. Formatting, strict locked workspace/
all-targets Clippy, all-target compilation and four debug builds pass. Source,
seven binaries and 21 embedded inputs match; native cleanup is verified.
Evidence is retained under `/tmp/mb-m6-sharded-joins-validation-omq9ys8p`.
Cache cleanup reclaims 8.65 GiB with binary hashes preserved. Full public/
private checkpoint selection, certified-current activation/retirement and
metadata/payload custody still need the sharded proof; complete metadata/
physical policy, normal producers/recovery and deferred capacity/platform
gates remain open. See ADR 0002.

Completed public format-two authority now joins sharded packing/coding with
exact original source authority and cumulative debt preserved. The typed proof
retains mixed legacy/paged revision cursors. A separate bounded draft format-ten
header carries the packing directory; original formats eight/nine stay intact.
Its candidate requires all completion markers, current coverage policy and
exact trusted event/Member records, including recovery keys and domains. It
still needs certified-current coding, legal history transition, live signing/
publication guards and all private/metadata/payload custody before activation.
Eleven new regressions pass. Frozen qualification passes 577 distinct cases:
191 core, 349 ordinary Store, 35 paged Node, the certified-writer migration case
and provisioned Btrfs native recovery. Formatting, strict locked workspace/
all-targets Clippy, all-target compilation and four debug builds pass. Source,
seven binaries and 22 embedded inputs match; native cleanup is verified.
Evidence is retained in `/tmp/mb-m6-public-directories-validation-hwecyke4`.
Incremental-cache cleanup reclaims 8.93 GiB with binary hashes preserved.
Complete metadata/physical policy, normal producers/recovery and deferred real
capacity/platform gates remain open. See ADR 0002.

The format-ten directory proof now reaches certified-current coding, original
history/authority transition and bounded quorum binding through the same
algorithms as formats eight/nine. Exact original lifecycle/witness and current
placement facts cover every global sector; complete history keeps its debt and
compares the predecessor's certified prefix. Directory predecessors retain their
original hashes/headers, with no invented flat roots. Real signed history covers
retire/forget/re-add, omitted old incarnations, later certified forks and identity
preservation across format-nine/ten predecessors. Signing/binding reread trust
and require the complete typed proof. Guarded publication still must require the
full history flag and integrate every private/metadata/payload role; normal
producers remain disabled. Eleven new cases pass. Frozen qualification passes
588 distinct cases: 191 core, 360 ordinary Store, 35 paged Node, the certified-
writer migration case and provisioned Btrfs native recovery. Formatting, strict
locked workspace/all-targets Clippy, all-target compilation and four debug builds
pass. Source, seven binaries and 22 embedded inputs match; native cleanup is
verified. Evidence is retained in `/tmp/mb-m6-directory-certification-validation-6g6tokyt`.
Cache cleanup reclaims 8.01 GiB with binary hashes preserved. Full metadata/
physical policy, durable activation/retirement and normal producers/recovery,
plus deferred dense capacity/platform gates, remain open. See ADR 0002.

The original-history/quorum directory proof now enters guarded public, private
and local READY payload custody through the original shared operations. Three
public roots and all nested source/descriptor/forest parts are pinned before
local I/O, with exact certificate readback, independent event/current-head
checks, immutable interrupted replay and bounded cancellation/release. A new
journal and pin prefix six preserve existing layouts; UUIDs cannot alias the
original private/payload backlinks across checkpoint layouts. Private and
physical custody spend the same cumulative budget in either acquisition order.
Node authenticates original authority, private metadata and complete READY
bytes, with real information/parity forget/rollback/reopen qualification.
Frozen qualification passes 191 Core, 369 ordinary Store and 38 paged Node
cases, certified-writer migration and provisioned Btrfs capture/recovery: 600
distinct cases. Original legacy information upgrade passes in the Node suite
and an independent repeat. Twelve new cases cover directory ownership and
local custody. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and four debug program builds
pass. Frozen Rust/Cargo source, seven binaries and 22 embedded protocol/helper
inputs match; native mount/loop/image cleanup is verified. Evidence is retained
in `/tmp/mb-m6-directory-custody-validation-i67_41gh`; the post-commit audit
binds the inputs to the commit.
Cache cleanup reclaims 10.07 GiB, leaving about 51.5 GiB in
`target`, with qualified binaries unchanged.
Complete distributed readiness and atomic activation, full metadata/physical
policy, normal producers/recovery and deferred dense capacity/platform gates
remain open. See ADR 0002.

Checkpoint custody now admits prospective private and physical dependency
work before authenticating their complete bytes. A read snapshot subtracts
original proof/public, private and other payload debt before original-witness
point replay. Each authenticated page is admitted before fetching and each
framed record before decoding. The publication writer rechecks all current debt
before byte validation and pin/counter publication. Exact same-role retries
reuse their existing charge; they still authenticate the witness and bytes.
Both original and directory layouts use these checks without changing signed
or journal encodings. Tests reject exhausted byte/page/record dimensions,
stop before an over-budget page fetch, reject damaged witness pages through
admission first, reject byte-validation callbacks in both acquisition orders,
and preserve exact-budget private/payload retries and counters.
Frozen qualification passes 192 Core, 369 ordinary Store and 38 paged Node
cases, certified-writer migration and provisioned Btrfs capture/recovery: 601
distinct cases. Formatting, strict locked workspace/all-targets Clippy, all-target
test compilation and four debug program builds pass. Source, seven binaries and
22 embedded inputs match; native mount/loop/image cleanup is verified. Evidence
is retained in `/tmp/mb-m6-custody-admission-validation-6my7zoqc`; a post-commit
audit binds the qualified inputs to the commit.
Removing 68 obsolete hashed workspace executables and incremental
cache reclaims 28.43 GiB, leaving 31.5 GiB in `target`. Current build outputs,
prior qualified paths and all seven qualified binary hashes are preserved.
The ordinary run leaves 26 Store and one paged Node case ignored. The native
case uses a sparse logical 1 TiB file on disposable Btrfs, without qualifying
dense retained capacity. Other ordinary/native suites and installed artifacts
were not rerun. Full distributed readiness/atomic activation, enclosing metadata/
physical policy including SQL/WAL/scratch headroom, normal paged producers and
seed recovery, and the deferred dense capacity/platform gates remain open.

Current Git mutation admission also shares capture's 39,488 data-position bound,
reserving 512 metadata positions from the 40,000-position flat format. It rounds
each reachable blob independently and conservatively assumes distinct sector
identities; cached lengths cannot prove capture's content sharing. Status names
this admission failure and retains full stock Git export. Recovery of existing
authenticated recipes keeps their original geometry. This interim check closes
another late capture failure but does not account for native namespace entries
or the complete private/signed envelope, so the full R2 contract remains open.

The user selected **1 TiB per protected dataset, including retained history**
as R3's first-release capacity target on 2026-10-06. This target applies to
the end-to-end capture, Git history, signing, packing, replay, retention and
seed-only recovery acceptance gates. It does not raise the current flat-catalog
limits or establish support before those gates pass. The catalog design must
also declare file/entry/history limits and memory/work bounds; a dataset byte
target alone does not bound the number of names, extents or references.
The authenticated page foundation and the consumer-migration sequence are
recorded in [the production catalog design](docs/adr/0002-production-catalogs.md).
The primitive is qualified independently; it does not change existing runtime
admission limits or close R2/R3.

Existing per-attempt coding and packed-sector decoders now bound collections
to their supported geometry, including the aggregate full-information witness
budget. Packed-cache writes borrow and encode one sector per SQL iteration in
one atomic transaction, with bounded local cache reads. Historical signed and
cache encodings remain unchanged. These compatibility safeguards remove an
extra batch of encoded cache records; complete flat packing/catalog collections
still require paged replacements, quotas and end-to-end consumer migration.
Validation is recorded in ADR 0002; the 1 TiB qualification remains open.

Retained legacy conversion now uses an explicit Node migration operation.
It keeps original signed revisions and flat heads, stages typed
private streams, orders public sources through an indexed SQL queue, and binds
authenticated stable data recipes with the new roots. The operation requires
the current certified writer, retains immutable retry/cancellation identity and
does not activate paged production checkpoints. Normal capture/restore and
packing/checkpoint/retention migration remain required.

The format-8 migration codec now authenticates a bounded public source root and
one encrypted private root descriptor with distinct owner/writer signatures.
The private descriptor carries typed native and optional Git roots without
publishing private plaintext page hashes. Source traversal checks the certified
writer fence, exact bootstrap source and authenticated EOF. Normal capture,
checkpoint, packing, retention and seed-only recovery still need to adopt these
roots together, with complete private/source joins and durable ownership before
activation. The codec alone changes no production protection claim or capacity.
Local publication now binds all three/six owned streams, the signed migration
record, completed native/source index and shared encrypted bootstrap in one
writer transaction. Typed cancellation fences them together and preserves
bootstrap ciphertext until its last owner retires. The migration namespaces
leave existing flat backup heads unchanged; full capture/replay and protection
activation remain required.

Sector rendering now resolves retained paged bootstrap ciphertext through one
indexed live owner. A single database snapshot checks signed identity, root/index
ownership and ciphertext; Node authenticates the seed, guild and private root
descriptor before serving bytes. Shared ownership survives individual revision
retirement and releases the source after its final owner cancels. No independent
legacy Inline recipe is created. Private page/file/blob source integration and
capture/recovery migration remain required before production format activation.

Private page traversal now binds a derived revision/sector source index within
the root-publication writer transaction. Explicit revision-scoped reads serve
encrypted index and leaf pages after checking retained member ownership, signed
source identity and both ciphertext commitments. Recovery repair authenticates
the page and rechecks its live binding and immutable metadata/child links under
the writer; cancellation fences this source immediately and index cleanup
reclaims one row per step. File/blob source adapters, legacy conversion and
production capture/checkpoint/recovery activation remain required.

Paged publication can now receive stable native/Git source recipes one signed
sector at a time. It verifies a bounded file range's scoped Data address and both
ciphertext commitments, then binds the recipe and physical anchor count within
the root writer transaction. Explicit revision/sector serving reopens signed and
private ownership before reading that range. Cancellation fences serving while
bounded cleanup releases one recipe and its shared anchor count together.
Native anchor retirement/replay and existing Git prune honor these pins; the
legacy prune bridge collects anchor identities. This uses the existing Linux
stable locator backend and leaves complete-source capture, Git blob/DAG checks,
normal consumer/retention/recovery migration and the real 1 TiB gate open.

Local data recovery can now conditionally replace a retained stable source after
authenticating replacement bytes under the writer. Source identity and a monotonic
local generation fence concurrent/stale attempts, including movement back to an
earlier recipe. The recipe and both physical anchor counts change together;
same-anchor range changes leave counts intact. Exact retries reauthenticate bytes
without repeating pin transfer. Canonical version-1 local bindings reopen at
generation zero; version-2 updates leave signed revision/private bytes unchanged.
Capture/recovery consumer activation and filesystem lifecycle qualification remain
required.

Whole legacy private conversion now authenticates the original bounded signed
revision and exact private encoding before staging native and optional Git
streams together. It preserves historical source addresses and signed/head state,
checks exact recipe/public-source joins, verifies source roots/commitments, and
hashes streamed sparse Git plaintext against its object ID. Both typed adapters
and combined root geometry preflight before external staging; interrupted sinks
retain caller-owned intents without publishing a migration revision. This Linux
adapter leaves production activation, automated new source authority/publication,
retention and the real 1 TiB gate open.

Historical data sources can now retain their original addresses under a new
paged revision. A bounded authority object verifies the original owner/writer
signatures and exact data membership before creating a legacy source binding.
Publication verifies the dataset, exact source and ciphertext commitments;
ordinary captures still require the scoped content address. Canonical local
recipes preserve the explicit address policy after reopen and recovery
replacement, using existing generation fences and atomic anchor pin transfer.
Original revision/head state remains intact. This completes the source adapter,
while whole retained-history migration, normal consumer activation, physical
source lifecycle and capacity/platform qualification remain required.

Ordinary sector serving now resolves retained paged private pages and stable
native/Git data by sector ID, in addition to bootstraps. Schema 10 installs a
partial source-row index transactionally over existing bindings; exact schema
validation includes its definition. Read-only older catalogs remain unchanged.
Lookup authenticates each candidate's root, source and pins in one snapshot,
skips valid cancellation journals and caps retired-owner work at 64 candidates;
excess backlog requires bounded source cleanup before retry. Missing or damaged
live ownership fails closed. The recovered-sector installer repairs owned private
pages through the existing fenced payload transaction and keeps live data under
its stable replacement policy. Complete normal capture/restore, data-source
recovery orchestration, packing/checkpoint/retention and seed-only migration are
still required before production admission.

Every supported legacy parity upgrade now checks its final schema-version write.
Rejected metadata rolls back table conversion and reservation creation together;
the old schema and shard bytes remain available for a clean reopen/retry.

The explicit retained paged Node API now restores Linux native trees by streaming
namespace and recipe pages with bounded disk-backed inode/link tracking. Sparse
offsets, raw names and forward hard links survive; an exact namespace check and
postorder directory metadata precede publication. The existing durable no-replace
publication journal distinguishes paged signed-body identities from legacy jobs
and can complete a rename after retained-source retirement. Git-bearing revisions
can restore their native portion, while Git-history installation, normal paged
capture, remote/seed-only restore, checkpoint/retention activation, quota policy
and real 1 TiB dataset/history qualification remain required. See ADR 0002 for
the consumer contract and validation.

Retained paged Git publication now requires complete ref/DAG/blob-membership
validation before publishing roots, and binds the Git repository to its enclosing
protected root. Streaming tree/header parsing and disk-backed graph traversal
retain bounded working memory for large individual objects and shared histories.
Blob plaintext verification, Git-history installation and the remaining normal
capture/packing/checkpoint/retention/seed-only consumers still require migration;
the first-release 1 TiB target remains unqualified. ADR 0002 records the graph
contract and its targeted validation.


Linux stable-anchor relocation now advances bounded process-local cursors without
holding the global area-index mutex during filesystem work. Streaming pinned
reads enforce mount boundaries and retain accessible-candidate ambiguity checks;
work/resource exhaustion returns explicit retry/location errors instead of source
absence. The index and shared directory-handle budget are bounded. Already native
Git catalogs keep unavailable copies for repair; unbound catalogs still require
provenance. Retained paged rendering now consults bounded durable raw-path hints;
ordinary serving remembers locations only after source authentication, and
explicit/read-only reads keep the catalog unchanged. Legacy stable rendering
also delays hint writes until successful verification. Ordinary Node serving now
checkpoints Linux Btrfs/ext4 scan cookies with filesystem/inode/change fences;
process/cache loss does not discard those cursors. Attempt/generation CAS,
bounded records/job count and atomic verified-hint/cursor completion fence
concurrent and interrupted writers. Native Git object lookup, catalog-backed
libgit2 reads, diffs, existing merge-blob verification and stock Git export also
use durable progress and saved raw-path hints; callbacks retain location hints
without owning a SQL connection. Control-aware root/file/blob capture, reconcile
and discard, Git staging/import/checkout replay, revision-anchor retirement and
Git prune now resolve through durable assistance without rewriting persisted
plans. Linux local control now provides bounded discovery-job inspection and
explicit reset for node and registered Git catalogs. Reset releases abandoned
quota slots and rotates a durable per-area fence, preventing old in-flight work
from resurrecting assistance after reset or completion. Git maintenance checks
existing registration/native ownership without replaying Git intents or
re-probing/rebinding the source backend. Remaining standalone capture/recovery
and best-effort cleanup integration, operational retry/backoff, other
filesystem/platform qualification,
full physical lifecycle and real 1 TiB dataset/history qualification remain
required.

The 2026-10-07 source-only review through `5f8c789` identified two R3 recovery
corrections. Both are now corrected and qualified as recorded below:

- **R3-MIGRATION-RECOVERY (corrected):** Explicit Node/library retained migration
  shares original flat data-sector IDs. Repair previously retried the missing
  native anchor even after reconstructing authenticated ciphertext. Historical
  bindings now permit an exact authenticated flat recovery recipe; ordinary
  restore/replay transfers retained sources to verified native replacements.
  Per-owner generation fencing and both anchor counts commit atomically, while
  a durable capture intent owns partially transferred output. Loss of the
  restored tree moves its pinned capture to retirement before a fresh retry.
  Native Btrfs verifies shared ownership, corrupt repair rejection, interruption,
  reopen, lost staging, stale replacements and unchanged signed flat records.
  The complete five-peer native Git gate verifies ordinary flat peer restore
  after normal owner startup with control preserved and source/anchors erased,
  then both complete owner losses, seed-only recoveries, exact Git interop and
  physical history/shard reclamation. The locked ordinary workspace passes
  900 tests on `270c040`; the test-only restart successor `b6e52bc` passes its
  complete peer gate in 527.82 seconds. Exact-source/binary and cleanup audits,
  formatting, strict Clippy and the all-targets build pass. ADR 0002 records the
  implementation and qualification scope.
- **R3-DISCOVERY-RESTART (corrected):** Reopening a saved relocation candidate with
  `PinnedDirectory::open` can return raw `Io(NotFound)` in
  `crates/mb-store/src/anchor/discovery.rs`. If that candidate moves within an
  already-scanned subtree while sibling traversal remains active, the remaining
  directory fences can stay unchanged. Durable retry reloads the same stale
  cursor because `crates/mb-store/src/database/anchor_discovery.rs` restarts only
  on `SourceChanged`. Both candidate reopens now map namespace changes to
  `SourceChanged`, preserving unrelated I/O errors and identity/marker fencing.
  A regression reproduces the old failure and verifies database reopen/retry
  without reset after a candidate moves inside its completed parent subtree
  while a 6,000-entry sibling scan remains active. Replacement/error mapping,
  existing reset/CAS and all other ordinary store tests pass (150 tests;
  26 provisioned tests remain ignored).

Continue normal paged capture/packing/checkpoint/retention and seed-only recovery
migration next. Milestone 6 remains open for that production pipeline, shared
admission limits and quotas, and real **1 TiB including retained history**
qualification. Preserve the remaining R1
legacy upgrade/export, R2 capacity, R5 topology/signature progress, R7 exact
release-artifact and native-platform gates. The review identified no other severe
regression in the inspected publication, native restore, Git graph validation,
scratch allocation, coding bounds or atomic cache-write paths. The review itself
ran no builds, tests or runtime probes; the subsequent correction qualification
above is separate evidence for its recorded source.

The next packing increment adds guild-scoped packed-sector descriptor streams
with 128-slot fragments, fixed record/root decode bounds and incremental checking
of historical sector IDs. Existing flat hashing also consumes canonical bytes
directly, preserving all five catalog layouts without a whole encoded copy.
Core compatibility/adversarial tests and durable store ownership/reopen/shared
root/cancellation tests pass (123 core, 153 ordinary store; strict Clippy passes).
The complete locked workspace passes 911 tests on `5579541`; its exact-source
Btrfs retained native recovery fixture passes in 28.07 seconds, with unchanged
source/binary hashes and verified resource cleanup. The all-targets build passes.
This implements a bounded codec prerequisite. Full source/proof/authority joins,
paged checkpoint publication, normal consumer migration, quotas and the real
retained 1 TiB gate remain required. ADR 0002 records the limits and evidence.

The source-proof codec now groups a single identity/commitment with bounded
64-proof fragments, verifying unique source order, complete chunk coverage and
every Merkle opening. Exact counts and EOF are mandatory; failures fence further
use. All 129 core tests and strict workspace/all-targets Clippy pass. This supplies
the second packing stream. Bounded disk-backed descriptor/proof/authority joins,
enclosing aggregate capacity, signed publication and consumer migration remain
the next production work; earlier workspace/native evidence above belongs to
its recorded descriptor source.

Compact packing roots now use stable 32-byte source keys and complete subtree
streams, preserving original sector IDs and commitments. Source insertion does
not renumber existing references. A fixed Merkle frontier verifies source and
packed composition. All 134 core tests and strict workspace/all-targets Clippy
pass; the conservative dense 1 TiB metadata calculation fits the existing 16 GiB
budget including page/index overhead. This is codec evidence, separate from
real retained data and full packing/coding/checkpoint admission. The bounded
store join and certified authority integration remain required.

The bounded store join now verifies full/compact descriptor and source streams
in a private encrypted scratch index. Every source chunk has exactly one checked
placement; virtual-zero hashes/roots and packed Merkle composition must match.
Both EOFs and an external source-authority callback are required before the
completion marker. Local bundles retain exactly both stream roles. All 134 core
and 158 ordinary store tests and strict workspace/all-targets Clippy pass,
including spill, fault rollback, quota retry and durable reopen/cancellation.
Certified paged authority, normal publication/retention/recovery activation,
coding/checkpoint capacity, quotas and real retained 1 TiB gates remain open.

The exact-source follow-up on `5841bd2` stopped at a Node coding-coordinator
reachability fixture failure (417 passed, one failed, 21 ignored). Its isolated
package-target retry passed in 193.62 seconds on a different feature-unified
binary; this is not a passing workspace gate. Separate locked store tests and
the workspace/all-targets build pass. Provisioned retained native Btrfs recovery
passes in 33.95 seconds with all 235 tracked-file and both workspace test-binary
hashes unchanged and resource cleanup independently checked. The fixture now
uses two Tokio workers to keep peer loops scheduled during synchronous packing
and certificate/GC work. Formatting and strict workspace/all-targets Clippy
pass; workspace requalification remains pending. Retain the original R5
progress and exact-release/platform requirements.

The packing join now has a trusted legacy-certificate authority bridge. It
bounds and verifies the existing certificate, preserves every retained source
and accepts eligible paged candidates only after owner/writer signatures,
base membership/fence/chain checks and complete source/bootstrap traversal.
Flat-only history needs matching owner or epoch-quorum evidence, or a new
signed paged source root. Exact source cardinality and commitment joins prevent
silent history omission. Source/candidate/placement cursors remain bounded in
the admitted encrypted index; aggregate admission includes the legacy envelope,
new source roots/pages, migration evidence and packing streams. Eight focused
authority tests and strict workspace/all-targets Clippy pass, including 16,002
sources, real spill and late-failure rebuild; full workspace requalification is
pending. This remains a proposal/migration bridge. Paged checkpoint authority,
private joins, current guild-event membership/writer fence rechecks, coding,
quotas, normal retention/seed-only consumers and real retained 1 TiB gates
remain required.

Exact-source qualification on `b509ac4` passes the locked workspace with 935
tests, zero failed, 116 ignored (418 ordinary Node and 166 ordinary store),
including the corrected mixed packed-group fixture. The locked all-targets
test build and provisioned retained native Btrfs recovery pass; recovery takes
29.68 seconds. All 236 tracked-file and both workspace test-binary hashes match
before/after, with runner and independent resource cleanup verified. This
supersedes pending workspace requalification above while preserving the original
R5, release/platform and real retained 1 TiB gates.

The checkpoint authority codec now streams ordered members, fences, retained
tombstones, mixed legacy/paged revisions and migration evidence. Original
legacy envelopes retain their signed bytes and identities behind bounded
authenticated references. Exact summaries include authority pages, fixed root,
legacy envelopes and paged source closures. The packing candidate cursor uses
the same numeric chain order with bounded indexed reads. All 140 core and 166
ordinary store tests and strict workspace/all-targets Clippy pass, including
1,000 chained revisions, member/signature limits, original legacy signatures,
corrupt tails and direct checked-candidate streaming; a fixed protocol root
vector records the layout. Enclosing paged certificates/coding, complete
authority joins and durable logical-reference ownership remain required before
normal publication/retention/seed-only activation. Capacity/quotas, incremental
work, real retained 1 TiB and original platform/release gates remain open.

Public logical authority roots now have a separate local retention journal.
The journal pins the authority byte tree, original legacy envelope trees and
signed paged source trees across scopes, verifies full typed control/body/source
EOF, and publishes its completion state only afterward. Fixed bounded records
and per-root transactions replace a whole-catalog root vector. Interrupted
builds replay after reopen; shared roots retain independent owners; cancellation
fences publication before one-root cleanup and ordinary bounded page GC. Six
focused fixtures pass, including 97 distinct roots beyond fixed bundle capacity,
capture-pin release, shared/reopened retirement, invalid signatures/bootstrap
entries, corrupt tails and ignored publication/acquisition/release writes.
All 140 core and 172 ordinary store tests pass (26 store tests ignored), with
strict locked workspace/all-targets Clippy and formatting/diff checks. Native
anchors/bootstrap ciphertext, coding roots, current certified checkpoint guards,
complete authority joins and normal consumers remain required before activation.

Variable-coding evidence now streams original signed transcripts through bounded
fragments in a public Coding forest. Group descriptors come from the original
manifests, and globally ordered groups remain intact within each part. Four
existing 16 GiB trees share a 64 GiB forest ceiling and one-million-page budget;
the enclosing checkpoint must also admit authority/packing/private-source work
under its combined policy. Complete replayed EOF and an external authorization
callback precede exact local bundle binding; ordinary atomic publication,
reopen, shared ownership and cancellation retain all forest parts. Nine focused
core tests and two store fixtures pass. All 149 core and 174 ordinary store
tests pass (26 store tests ignored), with strict locked workspace/all-targets
Clippy and formatting/diff checks. Fixed layout/original witness vectors preserve the
draft encoding. The conservative dense default 1 TiB coding-only metadata shape
fits the forest. This is separate from real retained-data/runtime qualification.
Fixed legacy coding groups, current delegation/source/lifecycle joins, the
enclosing certificate and normal consumers remain required before activation.

The bounded packing index now retains verified sector summaries and joins
complete replayed coding evidence to every current packed input in the same
admitted encrypted scratch store. Active non-virtual coverage requires exact
commitments, logical geometry and signed roots; retained/replacement groups stay
available through bounded original-witness range lookup. Explicit current versus
historical authority results preserve full-byte flat-root requirements. A single
combined descriptor charges packing/coding work under 64 GiB and one million
page occurrences; the certified wrapper preserves source-authority admission,
trusted base and candidate cursors. A completed proof binds both packing roots
and all coding parts in one atomic local bundle. Certified guild-event/lifecycle
validation, the enclosing certificate and full consumer/retention/quota/runtime
qualification remain required; this is a staging join. See ADR 0002 for validation.

A subsequent allocator/codec audit finds that single-owner 1 TiB admission
requires a different aggregate policy from the isolated fully occupied sizing
case. The existing reserved cross-owner slot requires 22,369,622 packed sectors
and 7,456,541 default coding groups. At supported maximum domain lengths, a
necessary lower bound is 1,021,270 coding leaves and 74,390,180,513 combined
packing/coding bytes, before signed source trees/private metadata/history.
This exceeds the current aggregate limits. The focused reproducible audit passes;
R3-SINGLE-OWNER-METADATA now records the required enclosing admission/directory/
quota correction. Consumer activation and actual retained-data qualification
remain gated on that complete design, without narrowing the 1 TiB dataset target.

Coding directories now retain the original bounded forests and signed witnesses
under one trusted byte/page/record traversal budget. The completed directory
join proves exact eligible packed-input coverage in the same admitted encrypted
index, carries the source-authority prefix and original witness locations, and
requires every nested EOF and external authorization. Directory and combined
structural fixtures remove the old single-forest admission assumption; they
remain synthetic lower-bound evidence, not a full retained 1 TiB policy or runtime
qualification.

A combined local metadata journal now requires that completed proof and binds
both packing roots, the directory and all logical forest parts. Initial roots
acquire atomically; bounded part acquisition precedes local witness replay, and
publication requires complete local packing/coding EOF. Interrupted jobs replay
with the exact proof/budget; cancelled cleanup releases one root per transaction,
preserving shared successors across reopen and capture retirement. Authority,
coding and combined journals share bounded ownership machinery while preserving
existing version-one layouts and pin namespaces. This remains local public
metadata ownership: certified-current checkpoint publication/retirement guards,
authority/private/native/bootstrap and information/parity payload ownership,
the full enclosing capacity/quota policy, normal consumers and the original
Milestone 6 closure gates remain required. Validation is recorded in ADR 0002
and TODO.md; the enclosing checkpoint-ownership item remains open.

The public authority stream now has a complete disposable join into that same
packing/coding index. It checks exact supplied certified-event membership,
historical/latest writer fences, first retained chains and tombstone suffixes,
global retained/retired revision IDs, original legacy/source/bootstrap EOFs,
source identity/geometry consistency and necessary owner/quorum migration
evidence. Its byte/page/record ledger survives every join; nested work is checked
before exposing an understated reference. Bounded mixed-revision and source
cursors preserve original identities without a flat legacy checkpoint or a
second scratch store. The event snapshot and fence authorization still require
independent certified history and live rechecks; full production certification,
the full authority/coding transition, private/payload
joins and complete publication/retirement ownership remain open. This does not
activate normal producers or change the required retained 1 TiB policy or gates.

A fixed version-eight public quorum header now binds the completed authority,
both packing roots, the coding directory and exact nested authority record
ledger. Its independent trust snapshot carries the certified event head and
sequence, active members/quorum, genesis and original previous checkpoint hash.
Store signing/binding requires completed current coverage, exact original member
records and fresh equal trust snapshots before and after the operation. One
32 KiB certificate envelope replaces local descriptor reservations under the
same shared admission; signatures and the roster have fixed 256-member bounds.
Header verification is explicitly separate from complete body validation and
the previous-state transition. This draft bridge has no normal producer or
publication/retirement capability; all remaining transition, private/payload,
ownership, quota and release qualification gates above still apply. Protocol
formats 3–7 and original signed identities stay unchanged. Validation is recorded
in ADR 0002 and TODO.md.

Paged header signing and binding now additionally require a private completed
public authority transition proof. It compares the exact independently trusted
legacy or paged predecessor through bounded encrypted-index cursors, preserving
original signed envelopes, fences and tombstone prefixes. Fresh revisions need
active membership and the certified-current nonrevoked writer; historical keys
and removed owners authorize only unchanged retained history. Both complete
public inputs and a conservative bound for indexed comparison work share one
trusted job budget. The transition is atomic in the disposable scratch store,
with no production writer held. This removes the raw public-body signing route;
coding lifecycle/fixed legacy migration, the full retention/quota policy,
private/payload custody and durable certified-current publication/retirement
remain gates before normal consumers or retained 1 TiB qualification. See
ADR 0002 for fixtures, including spill/exhaustion/rebuild across 4,096 fences.

The authority transition now also requires a completed exact certified-current
variable coding state proof. A bounded independent event snapshot supplies
complete retained/retired group counts, and fixed trusted history lookups match
every original group/profile, signed witness hash and lifecycle against the
completed directory. Unrelated and retired groups remain until certified
forgetting. Every packed sector's coverage must use current placement from that
same snapshot. One disposable transaction checks exact EOFs and rechecks trust
before issuing the proof; the authority successor carries its complete public
and comparison-work ledger forward. Bounded internal rows avoid per-point
descriptor rereads, with completion checks around the scan. This strengthens
the draft signing bridge, without activating normal producers. A production
bounded certified-history reader, fixed legacy migration, complete coding
transitions, quota/private/payload and atomic durable publication/retirement
remain required. No signed layouts or original group/witness identities change.

The draft joins now have a concrete bounded disposable original-history reader.
It starts at independently trusted original genesis, traverses bounded event
metadata/payloads to exact EOF, verifies original certificates and indexed state
effects, and compares the final roster/tip with an independently supplied compact
certified snapshot. Only the bounded roster stays in memory; encrypted indexed
rows retain membership epochs, writer/recovery history and variable groups.
Original coding witnesses and historical delegation are checked once during
replay, including original-signers legacy Add bindings. Final fixed coding facts
include exact lifecycle and current placement; revoked latest writer keys never
fall back to older incarnations. The draft coding join can consume this token
and carry its whole replay/prior-work ledger into authority validation. Failure,
stale trust or missing original evidence yields no completed projection.
The projection also retains fixed original event tips and all variable coding
incarnations, including forgotten groups. A bounded historical-prefix lookup
checks the exact original head, epoch/quorum and roster; indexed range reads
preserve an earlier incarnation after the same original ID is re-added. The
concrete history authority-transition route checks both complete coding states,
every retained writer fence and predecessor ancestry against that original
chain, then performs the existing revision/tombstone successor comparison.
It carries the replay ledger forward once and admits all additional history
comparisons before point reads. Actual quorum-bound predecessor/successor
fixtures cover a changed signed witness after Forget/re-Add, certified forks,
unavailable old incarnations and an empty legacy prefix. Fixed legacy groups
and legacy bodies omitting retained variable history fail closed pending their
explicit migration. The external-authorizer draft route remains available;
normal publication must require the concrete history checks.
This does not integrate normal consumers, publish a durable compact current tip,
migrate fixed legacy groups or own payloads. Incremental history maintenance,
archive retention/compaction, complete aggregate quota/retained 1 TiB and release
qualification remain required. See ADR 0002 for the validation evidence.

Ordinary Node membership consumers now have a durable compact event-authority
projection. Verified genesis installation, recovery and event ingestion publish
the bounded roster/tip with the original accepted records and pending-record
cleanup in one checked transaction. Active/historical member checks, coordinator
selection, guild summaries and peer-exchange rosters read the projection without
loading growing writer/recovery/coding vectors. Fixed SQL payload limits, local
checksum, original genesis binding, exact original tip and a final reread reject
malformed/stale projections. Stores without the projection retain the existing
legacy path until an accepted install/recovery/event publishes it; malformed
projections do not fall back. This is local authority projection, not a new
peer certificate or an indexed coding-history proof. Flat event mutations,
legacy historical replay, automatic legacy/downgrade projection rebuilding, durable
writer/recovery/coding indexes and atomic checkpoint publication still need
their bounded integration and the full remaining qualification gates.

Normal current and historical coding-attempt authority checks now consume
bounded rosters. Verified ingestion adds one immutable historical roster row
when membership/quorum changes, and advances a fixed completion marker in the
original event/compact-tip transaction. Rows preserve their original genesis
and exact original certificate bytes, with bounded SQL reads, local checksums
and final authority/row rereads. Missing or corrupt indexed epochs fail closed.
New guilds index from epoch one; older/recovered states declare their indexed
suffix and retain original legacy replay below it. Indexed checks avoid growing
writer/recovery/coding vectors and the old full-state historical cache while
preserving original plan signatures, historical placement, current epoch fences
and deadlines. Bounded legacy-prefix rebuilding, archive retention/quota,
durable key/group indexes, flat mutation replacement, checkpoint ownership/
publication and full retained-capacity/platform/release gates remain required.

Original guild-history effects now also have a durable incremental index.
Each accepted event prepares only its bounded affected point rows in disposable
encrypted scratch, reusing the original certificate, key, coding-witness and
lifecycle validators. Guarded point mutations and the verified-prefix marker
join the original event/state/roster transaction; publication rereads the
selected rows after its final mutation. The index preserves every original
prefix tip and coding incarnation, including forgotten/re-added groups. Normal
Node and reader shard serving, emergency-reader group lookup and the group
lookup in variable repair use fixed bounded retained-group reads, preserving
holder, payload-root and checkpoint checks. They do not decode the growing
flat guild-state blob when the index is current. New guilds advance normally;
older/recovered stores rebuild from verified original genesis in bounded steps
during peer reconciliation, requiring original event-bound evidence. An
incomplete prefix retains the explicit legacy compatibility reader; damaged
current rows fail closed. Local index checksums are corruption checks, never
new signatures or peer certificates. Complete flat mutation replacement,
key-reader integration, old-store compact-tip rebuilding, migration throughput,
archive retention/compaction, full quota policy, enclosing checkpoint custody
and all retained-capacity/platform/release gates remain required.

Normal key consumers now share a frozen bounded authority batch. Backup
admission/claim authority, DHT recovery publication, local bundle validation,
idle recovery-key registration and already registered retained-writer checks
read indexed point rows without decoding accumulated guild history. The batch
checks original genesis, compact current authority and original tail before
the point reads, then rechecks them and the completed history marker before
returning. Explicit
compatibility reads fence the exact legacy state bytes as well. Latest recovery
lookup never revives an older epoch after revocation; retained writer lookup
preserves the original public key after revocation/removal. Damaged or missing
registered point rows fail closed. Endpoint/probe/readiness, installed recovery
resume and legacy packing-attestation membership checks use bounded rosters;
signature-lock SQL reads have the existing event bound plus fixed lock overhead.
Actual key registration and event mutation, job queue scans, remote history
recovery and enclosing checkpoint production/ownership still need bounded
integration, quota admission and the complete retained-capacity/platform gates.

The original full-state fresh-checkpoint gate follows the same current-writer
rule as the paged original-history reader: select the greatest registered
epoch first, then reject it if revoked. Revoking the latest key never
reactivates an older epoch. Exact historical writer lookup is unchanged, so
certified historical recovery and revisions retained by a committed head or
its successor survive rotation/revocation. This corrects the legacy gate;
bounded enclosing checkpoint production and qualification remain required.

Concrete original-history-proven paged candidates now have one durable public
metadata owner. It retains the authority root, both packing roots, the coding
directory and every nested legacy/source/forest root, plus the exact original
quorum certificate. Completed proof debt and local typed EOF replay share the
admitted budget. Bounded independent event trust and the actual SQL predecessor
are checked inside every acquisition/publication transaction. Node uses its
frozen original-history index for these guards; current-head identity reads
exclude the certificate body and bound hash payloads in SQL. Cancellation and
each incremental root release check the actual current checkpoint before and
after mutation, including after reopen. Final release also retires the original
certificate atomically. This stages public metadata; complete private/native/
bootstrap and information/parity custody, certified-current activation and
successor retirement, full quota/admission policy and normal retained-capacity/
platform/release qualification remain required before enabling producers.

The owner can now retain one exact revision's existing authenticated local
private bundle, keeping its private roots, bootstrap and native/data-source pins
live through checkpoint sharing and reopen. Acquisition uses an indexed original
revision identity plus the concrete quorum/history proof and independent event/
SQL predecessor guards; Node also opens the owner-encrypted private descriptor.
Cumulative private root, bootstrap and dependency work consumes the enclosing
proof budget. Existing atomic data-source replacement can transfer physical pins.
Cancellation of the bundle is blocked until all checkpoint dependencies retire;
each bounded cleanup step releases one private dependency before public roots,
checking the actual current checkpoint before and after mutation. This preserves
existing local custody. Complete information/parity availability, transitive
history/ancestor ownership, certified-current activation, cooperative producers,
full physical/dataset/guild quota and retained 1 TiB/platform/release gates remain
open; normal paged checkpoint producers remain disabled.

The same candidate now retains actual local READY variable-profile information
or parity roles from its original certified coding witness. Node checks the
assigned holder, bounded active volume locator and full original Merkle
commitment. Acquisition and destructive volume operations hold the control
writer across physical READY checks or deletion, closing races between separate
databases. GC and attempt rollback preserve both payloads and active locators;
verified evacuation can move custody through its existing recoverable migration.
Normal uploaded information now records its verified original transcript hash
before READY activation, matching recovery. The new real-upload evacuation test
exposed that this evidence was previously absent. R4 is now closed again after
qualifying normal evacuation's authenticated upgrade of those already-READY
historical uploads. The upgrade binds actual bytes and identity to the exact
original signed transcript and original indexed membership roster, including
expired plans and later membership removal. Only the empty information marker
changes; original attempt and verification identity remain intact. Missing
original witnesses require recovery, incomplete original indexes require replay,
and damaged activation or parity evidence cannot be upgraded. The path never
falls back to unused flat history or a different coding witness.
Paired role dependencies survive sharing and reopen, and bounded cancellation
releases one payload before private dependencies and public roots with actual
current-head guards. Payload bytes, measured coding-point replay and local
dependency work share admission with the original proof/public/private debt.
This establishes individual local roles; complete distributed readiness,
transitive history ownership, atomic certified-current activation, cooperative
normal production/recovery, full physical/dataset/guild quota and retained
1 TiB/native/platform/topology/release qualification remain required.

### Historical implementation and validation record (before scope correction)

The following record preserves prior code and test evidence. References to
future guarded/FUSE work in this record are superseded by R1 and are not active
requirements. Current work is defined by the correction queue and the revised
Milestone 6/7 gates below.

The local Btrfs attribute regression now also verifies that an LF-only edit
is dirty, appears as raw bytes in `diff`, and restores the original CRLF bytes;
a child-process Btrfs regression also verifies raw add, status, diff, restore,
switch, fetch/pull/push under inherited global and environment conversion
settings, an external attributes file, and configured filters without executing
them. That regression now also exercises a system clean filter, repository
filter settings and `info/attributes` on the ordinary-Git side, raw native
content merge, linked-worktree checkout and merge, combined linked restore,
and primary hard reset. The broader
cross-command source audit is recorded in
[docs/git-byte-audit.md](docs/git-byte-audit.md), covering each supported CLI
command and the ordinary-Git bridge. The separate topology, guarded backend,
and platform gates remain open.
The guarded format-6 production recovery path now journals the restored-tree
handoff, binds signed virtual metadata to a durable mount intent, verifies the
captured anchors against signed sectors, and registers the recovered root only
through a supervised FUSE claim. The production job now installs recovered
sector recipes from that guarded capture without a preliminary reflink; local
ext4 and Btrfs interruption/reopen runs exercise handoff and mount-intent
replay, and the Btrfs run migrates an older reflink capture. Full network
seed-only guarded recovery, guarded removal/GC, and the platform gates remain
open. A five-member memory-guild check now reconstructs signed guarded sectors
from the remaining peers after deleting the old owner's data directory and
source tree; ext4 and Btrfs runs restore the view from the seed and serve its
exact bytes to the ordinary owner. A provisioned P2P recovery gate is still
required. Revision-anchor retirement now checks live signed revisions and
sector-recipe pins before transferring an anchor to cleanup; retirement replay
rechecks recipe pins before physical deletion. The guarded mount claim still
needs a data-preserving removal path before its root anchor can be retired.
A separate local Btrfs regression confirms that a stock Git peer's CRLF
worktree can yield an LF blob and that our import, checkout, restore, and export
preserve the exchanged LF blob and object ID. The Git-facing help explains that
we do not reverse conversions already performed by a stock peer.
The complete local Git acceptance script passed on exact source `1d961d5`:
all 62 ignored Btrfs Git library cases, Btrfs extent measurements, node
reopen/recovery and encrypted-history cases, stock-Git remote-helper exchange,
and five-daemon seed recovery. The disposable Btrfs mount, network namespaces,
firewall rules, and test daemons were cleaned up. Transient four-of-five coding
signatures and obsolete-loopback dial warnings appeared during the network
run, so the intermittent topology reliability issue remains open despite this
pass.
Source tracing found that older roster and Identify hints could re-add a direct
address after a signed endpoint update. The endpoint cache now retains signed
sets, including empty withdrawals, as authoritative until expiry. Its focused
and direct-to-relay regressions pass. The complete local Git acceptance gate
passed on exact commit `d49a0bf`, including all 62 Btrfs Git cases and the
five-daemon seed-recovery test in 1,617.54 seconds. The disposable Btrfs mount,
test daemons, network namespaces, and firewall rules were cleaned up. Loopback
retries and short signature quorums still appeared during topology transitions,
so the original intermittent missing-signer path remains open for diagnosis.
The provisioned Git acceptance run on `3155689` passed its Git-specific slices
but failed the five-daemon topology backup after the 5,400-second timeout
following relay-only storage recovery. Two later isolated smoke runs and the
complete provisioned Git script passed on `31018a0` with stricter 900/600-second
diagnostic backup timeouts; the latter passed all Git, node, stock-Git bridge,
and five-daemon checks. The original intermittent missing-signer failure is
still unexplained and tracked in TODO.md. Linked pull/merge and physical-prune
slice gates are closed. The complete provisioned reflink script passed on
`6caeb11`, closing the combined-restore slice. The expanded provisioned
reflink script passed on exact committed source `d53b4be` with the stricter
600-second diagnostic topology timeout, closing the primary and linked
restore/reset replay gate, including rejection of a wrong native anchor and
unverifiable legacy intent. Its temporary Btrfs and network resources were
cleaned up. The intermittent missing-signer failure and the broader guarded
edit and platform-backend gates remain open. A disposable FUSE passthrough
probe on `b53be0b` passed on ext4 and fresh local Btrfs, covering read-only
mapping, writable-open refusal, and lower-inode safety under read-only
`O_TRUNC` and `chmod` attempts. This establishes a host capability for the
planned guarded view. `eac567e` also proves ordinary-user read access through
the FUSE view while the private lower source remains inaccessible on both
filesystems. `e4f4147` passed a single-file FUSE write-detach probe on ext4
and fresh Btrfs: ordinary-user `O_WRONLY` and `O_RDWR` writes receive the
original source inode only after durable sparse detach, while the independent
anchor keeps exact captured bytes. `2cf0cb3` extends that probe to ordinary-user
owner `chmod`, pathname truncate, and `O_TRUNC` open; all five privileged FUSE
tests pass on ext4 and a fresh local Btrfs image, and the stored anchor remains
byte-exact. `7f52416` adds a single-file FUSE rename/unlink probe: rename
preserves the frozen anchor until a later write at the new name
detaches it; unlink leaves the exact anchor available. All seven privileged
FUSE probes pass on ext4 and fresh local Btrfs. `33e8171` adds a guarded
`fallocate` callback; ordinary-user allocation extends the editable source
without changing captured bytes, and all eight privileged FUSE probes pass on
ext4 and fresh local Btrfs. `7110990` adds inode/name dispatch and directory
listing for a flat two-file guarded-root capture. One file can be edited while
the other stays frozen, then renamed and edited through its own durable detach.
All nine privileged probes pass on ext4 and fresh local Btrfs; normal store
tests and strict locked workspace Clippy pass. `712a62f` adds nested-directory
lookup/listing and same-directory file rename through the guarded-root view;
ordinary-user read and later edit of a nested captured file preserve its exact
anchor and leave another file frozen. All ten privileged probes pass on ext4
and fresh local Btrfs. `4d5c804` routes cross-directory file moves through
pinned source directories, updating the file's visible path before a later
edit; tracked-name replacement fails without changing either source. An
uncertain move failure poisons the view. The ten privileged probes pass on
ext4 and fresh local Btrfs, with normal store tests and strict workspace
Clippy passing. `6147a32` builds the experimental view from a published
guarded manifest and stored plan, checking pinned source identities and anchor
availability. The two-file and nested probes pass on ext4 and fresh local
Btrfs through that constructor. The subsequent file-namespace journal writes
rename/unlink intent before mutating a pinned lower directory and reconciles
either side of the mutation on rebuild. Renamed and deleted entries survive
actual FUSE remounts on ext4 and fresh local Btrfs; a replacement identity is
rejected. The following slice publishes newly created files from anonymous
same-filesystem inodes after recording their identities.
Interrupted publication reconciles across control-database reopen, and
ordinary-user creation, rename, later writes, and FUSE remount pass on ext4
and fresh local Btrfs. Atomic replacement now exchanges the source and target
inodes under one durable intent, publishes both namespace records together,
and removes the displaced inode only after that publication. Replay covers
every exchange/publication/cleanup boundary; ordinary-user replacement of a
still-frozen file and cross-directory replacement preserve the captured
anchors through remount on ext4 and fresh local Btrfs. Directory creation now
stages a same-filesystem inode in the protected anchor area, records its
identity before worktree publication, and replays an interrupted creation
without accepting a foreign target. Ordinary-user nested creation and remount
pass on ext4 and fresh local Btrfs. Empty dynamically created directories can
now be removed through a durable identity-bound intent; restart finishes a
partially completed removal and refuses a foreign replacement. Nested removal
and remount pass on both filesystems. Captured empty directories now have
manifest-verified identities and durable removal tombstones; removing their
last child, then the captured directory, survives remount on ext4 and fresh
local Btrfs. Rebuild indexes captured and dynamic directories together by
recorded current path. A directory rename now writes an identity-bound intent
before moving the lower directory and publishes every tracked descendant's
new path in one transaction; replay completes either side of interruption or
rejects a foreign target. Ordinary-user FUSE probes move a populated captured
subtree beneath a dynamic parent, edit without changing its anchor, then move
captured and dynamic subtrees again across remounts. The 109 normal store tests,
12 privileged FUSE probes on ext4 and fresh local Btrfs, and strict workspace
Clippy pass. Remaining metadata and allocation modes, concurrent handles,
mount supervision/recovery, and guarded enrollment remain open. Guarded-view
rebuild now retains a captured file's owner `chmod`: while its lower inode is
frozen the view advertises its
capture-time mode; after the edit journal proves that inode independently
editable, the lower inode's durable mode is authoritative. A nested-file
ordinary-user probe checks the initial frozen visible mode and a later `0640`
mode after remount on ext4 and fresh local Btrfs. Formatting, 109 normal store
tests, all 12 privileged probes, and strict workspace Clippy pass.
Replacing an existing empty directory now records both native identities,
atomically exchanges their names, removes the displaced empty inode, and
publishes descendant paths and the target tombstone together. Replay handles
every exchange and cleanup boundary and rejects nonempty or foreign targets.
An ordinary-user FUSE probe checks refusal of a nonempty target, replacement
of an empty dynamic target with a populated captured subtree, and remount.
The 112 normal store tests, all 12 privileged probes on ext4 and fresh local
Btrfs, formatting, and strict workspace Clippy pass on this slice.
Owner `chmod` of the root, captured directories, and dynamic directories now
survives guarded-view remount. The root mode is a durable local view record;
the private lower root remains `0700`. Child directory modes come from their
unfrozen lower inodes. Ordinary-user probes pass on ext4 and fresh local Btrfs.
The virtual root-mode record still needs inclusion in encrypted owner revision
metadata before seed-only recovery and guarded enrollment can claim metadata
fidelity.
Writable FUSE handles now keep a descriptor for the inode detached before
open. Handle-based truncate and allocation use that descriptor after unlink or
atomic replacement, so they cannot reopen a changed pathname. The ordinary-
user two-file probe covers both cases, with 112 normal store tests, all 12
privileged FUSE probes on ext4 and fresh local Btrfs, formatting, and strict
workspace Clippy passing. Broader concurrent-handle schedules, mount
supervision, and protected recovery of the virtual root mode remain gated.
The ordinary-user two-file probe also verifies that `fchmod` through a
read-only descriptor detaches the source before changing its mode and leaves
the private anchor intact on ext4 and fresh local Btrfs.
The guarded view now reports real regular-file access/modified times and
accepts owner `utime` only after durable detach. A first-mutation probe verifies
nanosecond values and exact anchor bytes on ext4 and fresh local Btrfs; all 13
privileged guarded probes, 112 normal store tests, formatting, and strict
workspace Clippy pass. Protected metadata recovery remains to be done.
The two-file guarded-root probe additionally verifies that nanosecond access
and modified times on a created, atomically moved file survive view remount on
ext4 and fresh local Btrfs.
Root, captured-directory, and dynamic-directory access/modified times now
come from identity-checked lower descriptors, and owner `utime` applies to the
pinned directory. The nested ordinary-user probe checks nanosecond values
across FUSE remount on ext4 and fresh local Btrfs; 112 normal store tests,
all 13 privileged probes on both filesystems, formatting, and strict workspace
Clippy pass. Root mode remains virtual; the private lower root stays `0700`.
Protected root-mode recovery remains gated. The view now derives file and
directory `ctime` from native inode metadata at nanosecond precision, including
negative Unix timestamps; ordinary-user probes compare it with the lower
inodes on ext4 and fresh local Btrfs across remount. The 113 normal store tests,
all 13 privileged probes, formatting, and strict workspace Clippy pass. This
does not yet establish seed-only recovery of every mutable metadata field.
An ordinary-user shared writable mapping now proves first-write detach. Eight
simultaneous writable opens exposed the kernel's one-backing-registration-per-
FUSE-inode rule; the view now shares a backing ID across overlapping handles
and retains each handle's own descriptor. Mixed read-only/writable handles also
pass, including a read-only handle opened before detach. The 113 normal store
tests, all 16 privileged guarded probes on ext4 and fresh local Btrfs,
formatting, and strict workspace Clippy pass. Broader namespace interleavings,
mount supervision, and guarded enrollment remain open.
The two-file probe now holds two writable descriptors across atomic replacement
and unlink; handle-based truncate and allocation remain bound to the old inode
without changing the replacement or captured anchors on ext4 and Btrfs.
Guarded passthrough open and create now allow `O_APPEND`. Ordinary-user probes
verify that seeking to offset zero still appends after detach and on a newly
created file; all 17 privileged FUSE probes pass on ext4 and fresh local Btrfs.
A separate-process probe now kills the mounted FUSE daemon and confirms new
view access fails while an ordinary user remains unable to read the private
lower file. It passes on ext4 and fresh local Btrfs. Mount supervision and
recovered guarded enrollment remain open.
The guarded store can now persist a mount claim binding the captured lower
root, private placeholder inode, mountpoint, and view owner. It refuses a live
or foreign mount, then remounts a claimed dead FUSE view after daemon loss. A
privileged ordinary-user test passes clean and killed-process remount, lower
root denial, and placeholder replacement rejection on ext4 and a fresh local
Btrfs image. The 114 normal store tests, formatting, and strict workspace
Clippy pass. This store primitive still needs daemon lifecycle ownership,
protected mutable-view metadata recovery, and replayable root enrollment
before guarded capture can be selected.
The guarded mount now requests kernel default permission checking. A privileged
probe exposed that `allow_other` alone let an unrelated user read a `0700`
view; with permission checking, the unrelated read fails while the intended
owner still edits through durable detach and the original anchor remains exact.
The edit survives clean and killed-daemon remount on ext4 and fresh local Btrfs.
Daemon ownership and guarded enrollment remain gated separately.
The raw FUSE view is now crate-private, leaving the checked guarded mount
wrapper as its public path. All 18 privileged view probes now use kernel
permission checking and pass on ext4 and fresh local Btrfs; the claimed-mount
recovery probe also passes there. Normal store tests, formatting, and strict
workspace Clippy pass. Enrollment remains gated on daemon ownership and
protected view-metadata recovery.
Claimed-mount recovery now reconstructs its manifest from the sealed native
anchor catalog, then checks the durable plan and manifest claim before mounting.
The privileged recovery test reopens the control store and remounts after a
clean stop and a killed process on ext4 and fresh local Btrfs; it no longer
supplies the old process's manifest. An unprivileged store test rejects changed
sealed catalog bytes. All 115 normal store tests and strict workspace Clippy
pass. This covers local restart metadata, while seed-only recovery of mutable
view state and safe node enrollment remain open.
Guarded anchor retirement now checks that its mount claim has been retired.
The explicit claim transition verifies an unmounted, identity-matched lower
root and placeholder, persists a remount fence, and removes the claim before
the anchor can be freed. A privileged lifecycle test rejects retirement while
mounted, then stops and retires the view and its anchor on ext4 and fresh local
Btrfs. Node GC must still invoke this only after retained revisions and Git
pins release the source.
`b69ce33` further makes signed endpoint sets authoritative over persistent
bootstrap and attempt-scoped recovery hints, and prevents a pending dial to a
withdrawn direct endpoint from holding transport selection on direct. The
focused direct-to-relay regression and strict workspace Clippy pass. The full
provisioned Git gate passed on this exact commit, including all 62 Btrfs Git
cases and the five-daemon recovery test in 1,503.94 seconds; disposable mount,
image, daemon, namespace, link, and firewall resources were cleaned up. During
the topology test, the coordinator temporarily had four of five signatures at
event 36 while all four peers were connected, including the recovered storage
peer over RelayFallback. Read-only state copies showed matching proposal-lock
prefixes for event 37 on all five members. The guild advanced to event 42 and
the backup committed. Keep the intermittent signature-response issue open;
obsolete loopback retries continued but did not prevent relay traffic in this
run.
The next Milestone 6 correction durably accumulates individually verified
signatures for the coordinator's exact locked proposal across retry passes and
reopen. Plain guild lifecycle events and verifier-bound coding Adds request
only missing signers, then atomically remove partial signatures when the event
installs; they do not require all unanimous responses in one pass. A focused
reopen/invalid-signature regression, existing guild administration and coding
lifecycle tests, core guild tests, the locked all-target workspace suite
(313 passing `mb-node` tests), and strict workspace Clippy pass. The complete
provisioned Git gate passed on exact commit `9f3bee0`: all 62 Btrfs Git cases,
stock-Git bridge, node recovery checks, and the five-daemon topology/recovery
test in 1,547.13 seconds. A signer temporarily exhausted its transport tiers
and then rejected event 27 while its guild state lagged; two signers exhausted
transport tiers at event 39. The coordinator advanced and the backup committed.
Disposable Btrfs and network resources were removed. Keep the intermittent
5,400-second reliability case open pending stronger repeated topology evidence
or a correction for any signer that remains unavailable indefinitely.
The Git raw-byte command audit is complete in
[docs/git-byte-audit.md](docs/git-byte-audit.md). `702fe63` also supersedes
pending policy dials when a signed endpoint set changes within the same
transport tier, so an old attempt cannot delay the replacement or trigger
fallback after its eventual failure. The exact-source provisioned Git stages
passed: strict Clippy, 62 Btrfs Git cases, extent measurement, node recovery,
and the stock-Git bridge. The network script's first invocation stopped before
namespace creation because `/usr/sbin` was absent from PATH; a separate
invocation with the installed `iptables` on PATH passed the five-daemon
topology/recovery test in 1,536.31 seconds. Disposable local Btrfs and network
resources were cleaned. Partial signature quorums and old direct-address dials
still appeared before the backup completed; the intermittent reliability gate
remains open alongside guarded enrollment and platform backends.
`b25ae06` lets signed endpoint exchange continue independently while a guild
tail request waits for a slow peer; state-changing lifecycle reconciliation
still follows tail catch-up. Its local provisioned five-node QUIC/recovery
test and exact-commit isolated topology/recovery test passed, the latter in
1,637.58 seconds with complete resource cleanup. The topology again paused at
event 36 for over five minutes with a recovered peer reachable over
RelayFallback, then advanced and committed. This does not close the
intermittent missing-signer reliability gate.
`d0dddcb` adds one-minute progress warnings for long coordinator stages,
coding-worker steps, and the pending coding-coverage loop without changing
their retry behavior. Its exact-source isolated five-daemon topology/recovery
test passed in 1,647.75 seconds with 900-second per-backup diagnostic bounds
and complete disposable-resource cleanup. Coverage warnings showed event
sequences advancing through both recovered-topology backups; no worker step
crossed the one-minute threshold. The earlier 5,400-second stall remains
unexplained, so the reliability gate stays open.
`e65580f` installs a verified coding Add locally before peer dissemination,
starts peer installs concurrently, and bounds their eager wait to 20 seconds;
lagging peers can use event-tail catch-up. The focused five-domain activation
test and strict workspace Clippy pass. The complete local Git acceptance gate
passed on that exact commit, including 62 Btrfs Git cases, extent measurement,
node/Git recovery, stock-Git exchange, and five-daemon topology/seed recovery.
The topology reached event 43 but again showed transient short lifecycle
signature quorums and stale-address dials. The timeout branch was not observed,
and the historical missing-signer stall remains unexplained; keep the
reliability gate open.
`2b8c248` also installs a certified plain lifecycle event locally before
concurrent, 20-second-bounded peer dissemination. A focused test holds one peer
response open, verifies the local tail is available before peer sends, and
exercises the timeout; administration and coding activation regressions and
strict workspace Clippy pass. The isolated five-daemon topology and seed-only
recovery test passed on the same source in 1,490.34 seconds on fresh local
Btrfs, with complete temporary-resource cleanup. A signer still temporarily
exhausted transport tiers and then rejected event 25 as coming from a caller
other than the configured coordinator before later progress. This correction
improves post-certification dissemination, but does not explain that
pre-certification signer failure; keep the reliability gate open.
`1b3f42a` distinguishes guild-transition membership denial from coordinator
authorization and logs the recipient's local phase, event sequence, and
membership error without changing the decision. Its focused refusal and active
administration tests and strict Clippy pass; the isolated local topology gate
passed on that source in 1,428.25 seconds. `b3093a1` enables warnings for both
seed-recovered daemons and includes the recovered member's log in backup
timeouts. Its isolated topology/seed-recovery gate passed in 1,431.81 seconds
with complete disposable-resource cleanup. At event 27 the recovered relay
member had no installed guild or local checkpoint while its restore was still
underway, so it correctly refused to sign; after adoption it became Active and
the guild advanced. That transient denial is explained, but it does not prove
the cause of the earlier 5,400-second stall. Keep the reliability gate open.
`0d5af1d` lets majority-policy guild events proceed once `verify_event`
accepts their collected certificate and drops pending minority requests before
peer installation. Focused majority, administration, coding activation, and
slow-install tests and strict workspace Clippy pass. The isolated local
five-daemon topology and seed-recovery gate passed with that network code in
1,569.46 seconds, with complete disposable-resource cleanup. Its unanimous
guild still had transient short signature sets and transport exhaustion; the
historical long-stall gate remains open.
A retiring duplicate was found to queue new requests even with a separate
healthy selected connection; its retirement may wait for unrelated inbound
work. Exact-connection dispatch now bypasses that peer-wide hold, while a
scheduled preferred-tier promotion still waits briefly. The focused regression
proves the selected path dispatches during duplicate retirement. This may
explain a stalled signer request but does not by itself close the historical
five-daemon reliability gate; rerun that gate on committed source.
The complete P2P unit suite passes (135 tests, 2 provisioned tests ignored)
after its activation fixture waits for receipt cleanup and the intended pending
activation. Those waits exposed an existing race on the prior committed tree;
they do not change production activation decisions.
The isolated local five-daemon topology and seed-recovery test passed on code
commit `a870a46` in 1,497.88 seconds. Its recovered-topology backups committed
after transient missing signatures and coding-coverage waits, and all disposable
Btrfs and network resources were removed. Duplicate-retirement dispatch has
now passed a real topology gate, but the earlier 5,400-second signer stall is
not causally explained; keep that reliability gate open.
The guarded FUSE view now answers `statfs` from the pinned lower-root
descriptor, reporting real filesystem capacity and name limits. A privileged
ordinary-user `statvfs` probe and comparison with the native filesystem pass
on ext4 and a fresh local Btrfs image. The 115 normal store tests, formatting,
and strict workspace Clippy pass. Guarded enrollment still requires protected
mutable-view recovery and daemon lifecycle supervision.
The guarded sparse-detach replay test now injects `ENOSPC` after a staging
write. On ext4 and fresh local Btrfs, it leaves the original inode frozen
and the anchor byte-exact, then completes on retry. A separate privileged
test fills disposable 192 MiB ext4 and 384 MiB Btrfs images until actual
`ENOSPC`; a 32 MiB detach then leaves a partial staging file, frozen source,
and exact anchor, and replay succeeds after space is released. It verifies a
disposable marker, separate mount device, and 512 MiB capacity limit before
filling. A checked guarded FUSE mount now returns the underlying `ENOSPC` for
ordinary-user writable open and pathname truncate, rather than `EIO`. The
privileged test passes on fresh disposable ext4 and Btrfs images: the source
stays frozen and inaccessible through its private lower path, the anchor
stays exact, and a claimed remount permits the edit after space is freed.
All 18 guarded-view probes pass on ext4 and fresh local Btrfs, alongside
115 normal store tests, formatting, and strict workspace Clippy.
The daemon now recovers active guarded mount claims before it serves requests,
retains their FUSE sessions, and checks them every five seconds. It finishes
an interrupted claim retirement rather than remounting it. A privileged node
probe passes on ext4 and fresh local Btrfs: clean startup recovery, detection
of an externally detached view, a second restart, ordinary-user edit, and
claim retirement. This supplies daemon ownership for existing claims; guarded
root enrollment and seed-only mutable-view recovery remain unimplemented.
An ordinary-user pre-opened descriptor can still bypass a private lower path
if a frozen inode remains user-owned: `fchmod` can restore write permission,
and `/proc/self/fd` can reopen the same hard-link anchor writable. The mount
wrapper now rejects view-owned frozen anchors and lower child directories that
remain view-owned or group/other-accessible before publishing a new claim.
The refusal probe, all 18 privileged guarded-view probes, and daemon-owned
mount restart pass on ext4 and fresh local Btrfs; normal store tests and strict
workspace Clippy pass.
The privileged held-descriptor probe now confirms that manually moving a
captured file and lower directory into owner-inaccessible state prevents
`fchmod`, writable `/proc/self/fd` reopen, and lookup through retained root
and nested-directory handles. Search-only access through a nested handle also
blocks mount admission. An ordinary-user FUSE edit leaves the anchor exact. It passes
on ext4 and fresh local Btrfs, with 115 normal store tests and strict workspace
Clippy. A replayable ownership transition and signed recovery of mutable view
metadata are still required before enrollment.
First-mount admission now verifies all captured lower directories before
replaying view namespace journals. The privileged refusal regression checks
that an unsafe nested directory leaves a pending rename record untouched;
it passes on ext4 and fresh local Btrfs, alongside the successful
held-descriptor mount probe, 115 normal store tests, and strict workspace
Clippy. This closes the preflight ordering gap, not guarded enrollment.
A versioned lower-ownership record now captures the original identities and
owners plus pre-isolation modes and access ACLs before isolation can begin;
file-freeze journals separately retain the original file access state. Reopen
checks its plan binding; a changed frozen-file owner blocks cancellation and
anchor retirement until restored. The privileged reopen/retirement probe passes on
ext4 and fresh local Btrfs, as do 115 normal store tests and strict Clippy.
The record preserves rollback evidence, but the ownership transition and
signed recovery of mutable view metadata are still required for enrollment.
Frozen-file owner isolation now has a separate durable record before `fchown`
under the held write-exclusion guard. A root pass uses the original owner from
the lower snapshot and replays a partially isolated file set. Privileged
held-descriptor and partial-replay probes pass on ext4 and fresh local Btrfs;
ACL and file-capability cases fail before mutation. Frozen-file retirement
now replays UID/GID and access restoration after anchor unlink; interruption
after unlink and after `fchown` passes on ext4 and fresh local Btrfs. The
root-level retirement now preflights unchanged directory metadata and binds
changed file owners to their isolation records, then clears the lower-owner
snapshot after all file retirements. Restart after one file completed and a
changed-directory refusal pass on ext4 and fresh local Btrfs. The held file
guard also checks an unjournaled owner before unlink. This earlier path did
not cover private or user-modified directories; detached owner-isolated
files remain fenced. A separately selected owner-first root capture now
journals its private policy before the first file, revalidates each prepared
source under a new held write guard, and changes its mode and owner before
creating a hard-link anchor. Thus the initial proof guard may end without
leaving a user-owned immutable link; intermediate crashes replay or cancel
from durable file journals. Privileged interruption, root replay/retirement,
and ACL refusal pass on ext4 and fresh local Btrfs. The ordinary guarded
capture path still must not be selected for enrollment.
Directory isolation now journals its original ownership snapshot and private
UID/GID before any chmod/chown, then replays partial lower-directory changes.
Root retirement restores directory ownership and mode after frozen anchors
retire. Ext4 and fresh local Btrfs probes cover interrupted transitions,
retained ordinary-user directory descriptors, and default-ACL refusal; 116
normal store tests and strict workspace Clippy pass. First-mount admission now
compares every planned lower entry identity and each complete directory entry
set before FUSE namespace replay, excluding only the marked Git catalog. The
isolation pass checks the same inventory before and after ownership changes.
Normal unknown-entry and replacement cases pass locally, and privileged
first-mount/isolator refusal passes on ext4 and fresh local Btrfs, alongside
117 normal store tests and strict workspace Clippy. Remount now checks the
reconstructed visible name/inode map against every complete lower-directory
entry set after namespace replay and before mount publication. Privileged
extra-entry refusal and legitimate replace/rename recovery pass on ext4 and
fresh local Btrfs. A pre-replay descriptor walk now admits only inodes bound
to the capture, durable namespace records, or pending intents, and refuses an
unknown inode before a pending directory rename can mutate the lower tree.
Normal create/replace/rename crash states and privileged ext4/Btrfs remount
probes pass, alongside 117 normal store tests and strict workspace Clippy.
The pre-replay descriptor walk now also binds each lower name to its recorded
inode, allowing only the alternate names and descendants granted by a durable
pending namespace intent. It refuses a recorded inode moved to an ungranted
path before replay can mutate the lower tree; the later post-replay inventory
still checks the exact final namespace before mount publication. Normal
create/remove/replace/rename crash states, ext4 remount, and fresh local Btrfs
remount/replace/rename probes pass, alongside 117 normal store tests and strict
workspace Clippy. A detached named file now restores its original owner from
the durable isolation journal before returning a writable handle, replaying a
crash after detach; the focused privileged root test passes on ext4 and fresh
local Btrfs. Retirement now follows a captured frozen file's completed FUSE
rename record, rebinding the file capture to its verified current inode and
name before anchor removal. A same-directory ordinary-user rename, remount,
and retirement pass on ext4 and fresh local Btrfs; malformed or unfinished
namespace state refuses retirement. Captured-directory retirement now follows
completed move records and restores each planned inode at its verified current
path. A moved directory containing a frozen file survives remount and final
owner/mode restoration on ext4 and fresh local Btrfs, including a partial
owner-before-mode restore; malformed or replaced directories refuse retirement.
Captured directory removal/replacement now retires after a bounded lower-tree
inode-absence proof; a replacement directory restores its owner and mode at the
verified target path. Ordinary-user rmdir/replace, remount, and retirement pass
on ext4 and fresh local Btrfs. A detached capture's pending owner journal now
restores the original owner at a verified moved view name, or is released after
unlink/replacement only after a bounded lower-tree inode-absence proof. A
surviving moved name refuses cleanup. Ordinary-user remove, replace, move,
remount, and retirement pass on ext4 and fresh local Btrfs, alongside 118
normal store tests and strict workspace Clippy. Signed mutable-view recovery
and the complete privileged mount gate remain open before ordinary user-owned
roots can be enrolled.
The complete 18-probe guarded FUSE suite now passes on ext4 and fresh
default-atime Btrfs. A Btrfs failure showed that internal directory inventory
reads advanced a user-set atime during remount; pinned reads now request
`O_NOATIME` where permitted. The passthrough probe also places its temporary
parent on the provisioned filesystem. These local corrections preserve view
atime but do not provide signed recovery or finish guarded enrollment.
Internal inventory streams now reopen the pinned directory with an independent
read offset and identity check, so concurrent scans cannot consume each
other's entries. The interleaved-stream regression, 119 normal store tests,
strict workspace Clippy, and all 18 privileged FUSE probes pass on ext4 and
fresh default-atime Btrfs. Signed metadata recovery remains open.
Broader FUSE failure paths and guarded enrollment remain open.
M5-123 through M5-126 corrected live coding ownership and removed-holder
discovery. M5-127 passed local formatting, strict locked all-target workspace
Clippy and tests, Docker lab safety, all 23 fresh disposable Btrfs/network
acceptance invocations, and an independent resource cleanup audit on exact
code source `e09a13f`. All compilation and execution were local. The later
source-only review found uncovered retirement, placement and coordinator
replanning schedules; M5-127 remains evidence for its exercised cases.
M5-119 through M5-121 corrected negative verifier findings, cross-version
launch renewal and offline removed-holder cleanup obligations. M5-122 passed
formatting, strict locked all-target workspace Clippy and tests, Docker lab
safety, all 23 fresh local Btrfs/network acceptance invocations and an
independent resource cleanup audit on exact source `4880c28`. Renewal coalescing
(M5-118), acknowledged retry recovery (M5-116), confirmed cleanup (M5-117),
packed-input restaging (M5-113), cleanup/verifier arbitration and durable
submission reconciliation (M5-111/M5-112/M5-115) passed focused local
regressions and the complete M5-114 gate on exact committed source `720920d`.
The locked all-target workspace checks, Docker lab safety and all 23 fresh
local Btrfs/network acceptance invocations passed, and disposable resources
were independently checked after cleanup on exact source `720920d`. The earlier
M5-104 gate on `f8e47d3`, including all 23 provisioned invocations and verified
cleanup, remains passing historical evidence. M5-97 and earlier gates retain
their exact-tree results too.
The following records retain the correction and closure history. The M5-36
through M5-66 correction history and M5-45/M5-67 gates remain historical evidence.
Fresh source-only review of `81ec33b..b65c79a` found M5-68 through M5-76 and
reopened Milestone 5. Those implementation blockers are corrected, and the
complete local M5-77 workspace/provisioned gate passed on 2026-09-22.
Fresh source-only review of `b95811b..168945a` found M5-78 through M5-83 and
reopened Milestone 5. Those corrections and the complete local M5-84 gate
passed on 2026-09-25.
Source-only follow-up review of `b9d4e07..8434b30` and the then-local
node-source edits found a repeated-roster legacy rollback and missing gates.
Subsequent local correction commits `7ee8397`, `bb0d333`, `5076e8e`, and
`d1c94cc` fix that rollback, gate persistent high-head/lower-head fallback
across restart, exercise lazy legacy-evidence indexing, and release a failed
relay circuit before source denial completes. Later commits through `484e4ec`
add indexed long-history lookups, a streaming legacy journal, replacement
network-shard coverage, and a twelve-request stalled-STOP relay regression.
M5-78, M5-82, and M5-83 are corrected. Later commits `40d83ec` through
`e959d92` cover M5-79 through M5-81's peer, recovery, and packing resource
gates. Fresh source review and the complete M5-84 local gate passed on
2026-09-25. A further source-only review found M5-85 through M5-87 in that
source tree. The earlier gate remains historical evidence. M5-85 and M5-86
are corrected in `e9fadb2` and `75d0fd5`; `1e8ee2b` and `dd5c7e8` correct
M5-87. The complete M5-88 gate passed locally on 2026-09-25, closing
Milestone 5 for that source tree. Later source-only review found M5-89 and
M5-90. Both are corrected in `e63d538` and `09e9379`; the complete M5-91
local gate passed on the latter source tree. Further source-only review found
M5-92 through M5-96; Milestone 5 is reopened and Milestone 6 waits for M5-97.
Commits `1998700` through `308b156` correct the live-quorum, restore, and
mixed-coverage paths and tighten legacy root checks. Source-only review of
`308b156` found that new legacy checkpoint signing still trusts a format-2
flat-root claim when its role commitment matches a separately signed revision
commitment. The model does not establish that the two revision roots describe
the same bytes. M5-92 and M5-96 remain open, and M5-97 has not run on this tree.
Commit `c7cc6fd` introduces a version-three coding plan and a version-two
manifest carrying complete encrypted information bytes only when flat-root
binding is needed. Replay checks both roots against those bytes. New legacy
variable and old flat-root packed checkpoint coverage requires this proof;
compact production packed coding remains unchanged. Focused local regressions
pass for forged claims and retained revisions. M5-92 and M5-96 are corrected,
and M5-97 remains the closure gate. Source-only review of the follow-up through
`e64f76e` finds migration and encoded-frame blockers M5-98 through M5-100.
Stronger legacy proofs must have a usable durable attempt/group upgrade path,
preserve historical recovery, and fit every containing peer message before
the complete local gate can close Milestone 5.
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

- **M5-36 (resolved):** Version-four owner revisions sign source Merkle
  commitments, and version-two packed catalogs prove each aligned slot against
  them. Checkpoint validation recomposes packed commitments from those proofs,
  so substituted source bytes are rejected before approval even when the owner
  is absent. Legacy revision and catalog encodings remain readable.
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
- **M5-43 (resolved):** Content-scoped sector identities safely reuse unchanged
  ciphertext. No-change revisions advance catalog metadata without payload or
  coding work; changed revisions fetch only new sources and load/write only
  affected packed sectors. Metrics and focused multi-owner tests bound source
  reads, transfer, coding work, durable bytes, and peak payload memory.
- **M5-44 (resolved):** Production groups batch adjacent packed sectors into
  full real-information lanes and balance holders across reachable,
  capacity-bearing failure domains. Information and parity share one capacity
  ledger. Assigned information is durably staged and activated on configured
  volumes, while the finalized coordinator drops its packed payload cache.
  Incremental packing reads only changed prior sectors from certified holders,
  and stable descriptors retain their existing groups. Focused coverage bounds
  coordinator storage and all information/parity debits and verifies repeated
  geometry.
- **M5-45 gate finding (resolved):** Content-derived sector IDs may repeat when
  a revision contains identical plaintext sectors. The legacy signed-network
  fixture now creates one coding group per distinct sector, and recovered
  anchor validation compares every distinct ID and exact reference without
  rejecting repeated identical references. The provisioned signed commit and
  seed recovery regression passes after the correction. The provisioned
  multi-owner workload now asserts exact active packed-sector coverage,
  bounded three-input group count, and at least one real multi-input lane; the
  real-QUIC scenario passes with those M5-44 invariants.

The final corrected tree passes `cargo fmt --all -- --check`,
`cargo test --locked --workspace --all-targets`, and
`cargo clippy --locked --workspace --all-targets -- -D warnings`. A fresh
locally provisioned 2 GiB Btrfs image passes the complete
`scripts/reflink-acceptance.sh` gate, including every provisioned filesystem,
interruption, headroom, relocated recovery, five-node seed recovery, signed
network recovery, repeated multi-owner QUIC, and five-daemon namespace/NAT/DHT
recovery scenario. This closes M5-45 while preserving anti-equivocation,
seed-only recovery, retained-layout readability, failure-domain separation,
and storage/transfer bounds. All compilation and execution were local; no
remote compilation server was used.

Follow-up source-only review of `56bb57d..f7d0503` on 2026-09-20 reopens
Milestone 5. Exact source locations and correction gates are in `TODO.md`:

- **M5-46 (resolved):** Checkpoint completion requires enough staged/finalized
  holders for the seed-recovery publisher rule, disseminates certificates to
  nonsigners, and periodically catches rejoining members up over verified
  parent chains.
- **M5-47 (resolved):** A fast empty event tail preserves other requests for
  their bounded logical lifetime, allowing a slower relay or Tor path to
  advance the local event head.
- **M5-48 (resolved):** Automatic backup persists per-root quiet/attempt state
  and selects the oldest eligible dirty root, including after restart.
- **M5-49 and M5-50 (resolved):** Revision format 5 derives stable IDs with a
  separate owner-secret key and protected-root scope. Same-root unchanged data
  retains reuse, cross-root recipes no longer collide, public plaintext guesses
  do not reproduce IDs, and legacy revision formats remain readable.
- **M5-51 (resolved):** Current format-7 signing requires a root-bound
  authenticated version-3 or migration version-4 catalog. Historical
  version-1 and version-2 catalogs remain readable, but a new checkpoint cannot
  introduce or downgrade to one.
- **M5-52 (resolved):** Owner-signed migration bindings authenticate retained
  version-3 revision bytes once, remain reusable in version-4 catalogs, and
  keep prior packed copies available for later repacking and restore.
- **M5-53 (resolved):** Incremental and replacement packed reads use bounded
  any-`k` reconstruction and verify the reconstructed catalog commitment.
- **M5-54 (resolved):** Current catalogs use the authenticated Merkle root as
  their canonical packed root, reject a distinct `flat_root`, and carry that
  root through coding plans and checkpoint coverage.
- **M5-55 and M5-56 (resolved):** A whole-run domain-capacity planner accepts
  feasible fragmented capacity, rejects infeasible demand, orders lanes by
  adjacent catalog index, and reuses compatible holder geometry across runs.
- **M5-57 (resolved):** Relay reservation responses are serialized, provisional
  admissions cannot receive circuits, and pending renewals retain their bounded
  capacity claim across expiry until acceptance settles.

At that correction stage, the fresh local tree passed `cargo fmt --all --
--check`, locked all-target workspace tests, and warning-free locked all-target
workspace Clippy. The provisioned Btrfs/network acceptance gate had not yet
been rerun after M5-46 through M5-57, so later review and correction continued.
All compilation and execution was local; no remote compilation server was used.

Fresh source-only review of `f7d0503..81ec33b` on 2026-09-21 found that the
correction series does not yet close Milestone 5. Exact source locations,
failure scenarios, and correction gates are in `TODO.md`:

- **M5-58 (resolved):** Verified quorum certificates can atomically adopt the
  exact signature lock, so reachable nonsigners become durable holders and
  publishers without weakening transition checks.
- **M5-59 (resolved):** Intermediate checkpoints validate against the authority
  and complete member history recorded at their epoch even after event-first
  synchronization advances the current authority.
- **M5-60 and M5-61 (resolved):** Selection considers only dirty roots with
  schedules and checks each root's remaining byte-budget fit before choosing
  it. Oversized roots retain a root-local next-window retry while smaller
  eligible siblings proceed.
- **M5-62 (resolved):** Version-4 catalogs enter the authenticated complete-corpus
  updater, which emits version 3 after the final legacy source retires without
  dropping unchanged modern sources or retaining unused bindings.
- **M5-63 (resolved):** Current checkpoint members can quorum-attest a legacy
  source reconstructed from certified any-`k` storage when its historical owner
  is absent. Accepted attestations are journaled before publication and reused
  after restart.
- **M5-64 (resolved):** Changed backups during migration recover unavailable
  retained sources and changed packed sectors through the certified-placement
  any-`k` loader with catalog commitment checks.
- **M5-65 (resolved):** Relay reservation responses have a fixed per-connection
  bound, independent fair polling ahead of new inbound work, stream timeouts,
  provisional-admission cleanup, and overlap rate accounting.
- **M5-66 (resolved):** Peers serve retained certified ancestors, while a
  durable cursor and generation index bound both backward fetch and forward
  installation to 1,024 checkpoints per pass and resume after restart.

This review found no separate remaining blocker in M5-47 event-tail lifetime,
M5-49/M5-50 scoped secret content identities, M5-51 catalog authorization,
M5-53's version-2/3 any-`k` loader, M5-54 root binding, or M5-55/M5-56 placement
planning. It ran no builds, tests, daemons, runtime probes, or remote
compilation. The earlier local gate results remain historical evidence for
their exact trees and do not close these source blockers.

After correcting M5-58 through M5-66, the final M5-67 gate passed locally on
2026-09-22: formatting, locked workspace all-target tests, warning-free locked
workspace all-target Clippy, Docker lab safety, and the complete provisioned
`scripts/reflink-acceptance.sh` suite on a fresh disposable 2 GiB Btrfs image.
The provisioned run passed all anchor/reflink and node interruption/headroom
cases, five-node seed recovery, signed network recovery, repeated multi-owner
QUIC backup, and five-daemon namespace/NAT/DHT recovery. No remote compilation
server was used. This was the M5-67 closure record.

Fresh source-only review of `81ec33b..b65c79a` on 2026-09-22 reopened that
closure with M5-68 through M5-76. Exact source locations, failure scenarios,
and correction gates are in `TODO.md`:

- **M5-68 (resolved):** Current authority is mandatory for normal and final
  target commits; replayed historical authority is scoped to nonfinal catch-up
  links.
- **M5-69 (resolved):** Historical link validation replays authority, writer,
  and coding-group state at matching event-history snapshots.
- **M5-70 (resolved):** Targets are locally authorized before persistence,
  bound to their advertising source, and abandoned on failed evidence or link
  installation so another candidate can be selected.
- **M5-71 (resolved):** Quorum-endorsed forward generation lookup commits each
  link immediately, bounds each pass to 1,024, and stores no uncommitted
  certificates.
- **M5-72 (resolved):** Catch-up metadata has no certificate payload, legacy
  staging is cleaned on resume, and finalization acknowledges only an exact
  durable head and signature lock.
- **M5-73 (resolved):** Epoch-bound legacy evidence refresh recovers and
  verifies bytes from the prior authenticated packed catalog before using an
  original-source coding fallback, so owner and old-group retirement no longer
  strand the next checkpoint.
- **M5-74 (resolved):** Original and packed recovery deterministically try all
  matching active placements, prefer current geometry, and accept only a
  commitment-valid reconstruction.
- **M5-75 (resolved):** Version-3 through version-5 catalogs advance metadata
  without packed rewrites, unchanged authenticated sources skip payload reads,
  identical descriptors remain reusable, and evidence refresh retains bytes
  only for sources that actually require repacking.
- **M5-76 (resolved):** The relay handler polls reservation expiry before every
  replenishable source of work; the focused priority regression, complete
  vendored relay crate tests, and warning-free all-target relay Clippy pass.
- **M5-77 (passed):** The corrected tree passed formatting, locked all-target
  workspace tests, warning-free locked all-target Clippy, Docker lab safety,
  and the complete fresh provisioned Btrfs/network acceptance gate locally.

The source review ran no builds, tests, daemons, runtime probes, or remote
compilation. After the corrections, M5-77 passed locally on 2026-09-22:
formatting, locked workspace all-target tests, warning-free locked workspace
all-target Clippy, Docker lab safety, and the complete provisioned
`scripts/reflink-acceptance.sh` suite on a fresh disposable 2 GiB Btrfs image.
The provisioned run passed all 12 anchor/reflink cases, all seven node
interruption/recovery/headroom cases, five-node seed recovery, signed network
recovery, repeated multi-owner QUIC backup, and five-daemon namespace/NAT/DHT
recovery. The disposable filesystem was removed afterward. No remote
compilation server was used. This was the M5-77 closure record for its exact
tree.

Fresh source-only review of `b95811b..168945a` on 2026-09-25 found these
remaining blockers; exact source locations, failure scenarios, and correction
gates are in `TODO.md`:

- **M5-78:** A persistent higher head with missing intermediate evidence is
  reselected every pass, starving a lower complete checkpoint candidate.
- **M5-79:** Each generation lookup loads and verifies the entire retained
  checkpoint history, making long catch-up quadratic and one request unbounded.
- **M5-80:** Restore and cold recovery still use or require stale retained
  coding groups before trying a healthy current replacement.
- **M5-81:** Each legacy source repeats a full durable attestation-journal scan
  even when the prior catalog already has current evidence, making unchanged
  large-corpus packing quadratic.
- **M5-82:** Relay outbound STOP worker overflow retains a CONNECT request
  without a future that can report failure and release its circuit slot.
- **M5-83:** Historical catch-up can accept a revoked authority epoch after a
  later epoch because checkpoint transitions do not enforce epoch monotonicity.

This review ran no builds, tests, daemons, runtime probes, or remote
compilation. M5-77 remains historical evidence; Milestone 5 is reopened and
requires these corrections plus the new M5-84 local closure gate.

Source-only follow-up on 2026-09-25 found the M5-78 through M5-82 correction
paths in the current source, but the requested persistent-head, long-history
peer-lookup, unavailable-stale-group restore/recovery, measured large-corpus,
and stalled-STOP overflow gates are still missing. M5-83 remains a source
blocker: the local legacy-transition helper maps a format-4 checkpoint to the
earliest matching member roster, so A -> B -> A history can conceal an epoch
rollback to B. The complete M5-84 local gate must follow the final correction.
This follow-up ran no builds, tests, daemons, runtime probes, or remote
compilation.

The next local correction series closes M5-78 and M5-83: candidate-specific
generation endorsement and a signed high-head/lower-head restart regression
prove fallback, while the latest matching legacy member epoch rejects an
ambiguous A -> B -> A rollback after restart. Relay outbound failure now
releases circuit capacity immediately, independent of source-denial progress.
Focused node and relay tests and strict all-target Clippy passed locally for
these changes. At that point M5-79 long-history peer lookups, M5-80
unavailable-stale-group restore/recovery, M5-81 measured corpus bounds, M5-82
stalled-STOP overflow, and the complete M5-84 gate remained outstanding.

Source-only review of `ae9e6c3..484e4ec` on 2026-09-25 finds the M5-82
stalled-STOP overflow regression covers twelve requests on one destination
connection and observes shared circuit capacity released after each overflow.
M5-79 now has 1,024 committed signed generations read after restart and
repeated absent lookups, but no long-history peer catch-up resource gate.
M5-80 exercises network reconstruction and the production coverage helper
with an unavailable stale group, but not full restore and cold seed recovery
under that condition. M5-81 streams the journal and reuses its verified index
across 130 mixed sources, but lacks measured row-read, signature-check, and
peak-memory bounds for a full packing pass. The complete M5-84 local gate
remains outstanding. This review ran no builds, tests, daemons, runtime
probes, or remote compilation.

Subsequent local correction commits close M5-79 through M5-81. Signed peer
requests read every generation of a 1,024-link committed history after restart
and repeat an absent lookup 128 times; the request path reads one indexed hash
and one certificate. A packed snapshot with stale groups ordered first restores
through current replacement shards, and the same fixture runs production cold
shard recovery with replay-verified replacement transcripts. The complete
unchanged-catalog packing pass over 130 mixed legacy sources makes one
138-row/138-signature journal scan and keeps its peak encoded journal payload
under 512 KiB, with one transient row beyond the retained index. Focused tests
and strict node Clippy passed locally. Fresh source review of the final
correction commits found no new blocker. Formatting, locked all-target workspace
tests, strict locked all-target workspace Clippy, Docker lab safety, and the
complete fresh disposable local Btrfs/network acceptance script passed on
2026-09-25. No remote compilation server was used. M5-84 was recorded as a
closure gate for that source tree.

New source-only review after `890d88c` found three remaining failures in the
same code. Checkpoint catch-up de-duplicates equal advertised head hashes before
trying a second advertiser, although the first can have no intermediate links.
Legacy format-4 epoch inference uses all subsequently synced guild events, so
a valid format-5 successor can appear to move backward after a later quorum
change. Cold recovery counts replacement-group coverage only if the recovering
node has a shard role there; a former parity holder can therefore be forced to
recover an unavailable stale group. Exact source locations and correction
gates are M5-85 through M5-88 in `TODO.md`. This review ran no builds, tests,
daemons, runtime probes, or remote compilation. M5-84 remains historical gate
evidence; Milestone 5 is reopened and Milestone 6 waits.

Source-only review of `85822cb..1e8ee2b` found M5-85 and M5-86 corrected.
M5-87's new coverage-only plan fetches one live information shard, but that
fetch can return before checking `k` reachable shards. The coverage loop then
accepts all of the replacement group's sectors, so a multi-live-sector group
with only the probed holder available can hide an unavailable stale group.
The new parity-only regression has one live sector and cannot expose that
case. M5-87 remains an implementation blocker; M5-88's full local gate must
run on the corrected source tree. This review ran no builds, tests, daemons,
runtime probes, or remote compilation.

Commit `dd5c7e8` makes coverage-only cold recovery skip the direct-shard
shortcut and wait for `k` distinct verified shards, including authenticated
virtual-zero roles. A two-live-sector regression rejects one reachable shard
and accepts two; the six-member parity-only cold recovery regression still
passes locally. Fresh source review found no further blocker in M5-85 through
M5-87. The complete M5-88 local closure gate passed on 2026-09-25:
formatting, locked all-target workspace tests, strict locked all-target
workspace Clippy, Docker lab safety, and the full provisioned acceptance
script on a fresh local Btrfs image. Its repeated multi-owner QUIC backup and
five-daemon seed/DHT recovery smoke tests passed. The disposable mount, loop
device, image, and network namespaces were removed. No remote compilation
server was used; Milestone 5 was closed at that point.

Further source-only review of `85822cb..2eb6271` found two cold-recovery
blockers despite the successful M5-88 gate. Coverage-only plans match current
groups to checkpoint sectors by ID alone. A certified legacy group with the
same ID but a different authenticated root can be treated as replacement
coverage for an unavailable correct stale group. Separately, the planner adds
every overlapping current group and waits for all of them even when one has
already supplied sufficient coverage; the number of overlapping certified
groups is not bounded by dynamic-state validation. Exact source locations and
correction gates are M5-89 through M5-91 in `TODO.md`. This review ran no
builds, tests, daemons, runtime probes, or remote compilation. M5-88 remains
historical gate evidence for its exact tree; Milestone 5 is reopened and
Milestone 6 waits.

The M5-89 and M5-90 corrections bind cold replacement coverage to exact
checkpoint sector authentication and schedule only bounded, useful current
groups. Fresh source review found no further blocker. The complete M5-91 gate
passed locally on source commit `09e9379` on 2026-09-25: formatting, locked
all-target workspace tests, warning-free locked all-target workspace Clippy,
Docker lab safety, and the full provisioned acceptance script on a fresh
disposable 8 GiB Btrfs image. Repeated multi-owner QUIC backup and five-daemon
seed/DHT recovery smoke tests passed. The mount, loop device, image, and smoke
namespaces were removed. No remote compilation server was used. Milestone 5
was closed for that source tree at that point.

Further source-only review of `6bc66bd..543fb9b` on 2026-09-25 found five
remaining blockers. A format-2 transcript's claimed legacy root can be
accepted without binding it to committed information bytes; a current recovery
plan with all local targets READY can receive coverage without proving live
`k`. Ordinary restore stops at a reachable same-ID wrong-root group instead
of trying a correct older placement. A mixed group can be rejected for an
already-covered wrong-root sector even though another sector in the group is
valid and needed. Finally, retained-revision checkpoint validation can count
a wrong-byte rootless format-1 replacement as protection, and audit can report
it healthy. The exact source paths and correction gates are M5-92 through
M5-97 in `TODO.md`. The review ran no builds, tests, daemons, runtime probes,
or remote compilation. M5-91 remains historical evidence for source commit
`09e9379`; Milestone 5 is reopened and Milestone 6 waits.

Source-only review of the full-byte legacy-proof follow-up through `e64f76e`
on 2026-09-26 finds three further blockers. Format-3 plans reuse format-2
attempt IDs, conflicting with durable interrupted jobs. Identical bytes and
placement also reuse the certified group's ID, whose immutable transcript
record rejects the stronger evidence. Finally, the 512 KiB raw witness limit
does not account for CBOR integer-array expansion or containing peer-message
overhead, so accepted profiles can exceed the 600 KiB transport frame.
M5-98 through M5-100 in `TODO.md` specify the correction and regression gates.
M5-92 through M5-96's authentication corrections remain implemented, but
Milestone 5 is unfinished until migration and transport work and M5-97 pass.
This review ran no builds, tests, daemons, or runtime probes and used no remote
compilation.

The M5-42 rejected-connection cleanup was source-reviewed and found to remove
only the rejected connection while preserving accepted siblings. This review
ran no builds, tests, daemons, runtime probes, or remote compilation.

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

### Milestone 5 — efficient and flexible data/guild protocol (closed after M5-152)

The historical source-only review through `a6b5d7d` found three blockers in
the recently changed coding ownership and cleanup paths. A replayable negative
verifier transcript entered an activation job; after holder abort,
`complete_coding_activation` terminated the parent retry and removed its input
intent, while a later launch for the same lane rejected that negative evidence
(M5-119; `node.rs:5494`, `:5840`, `:6291`, `:4019`). Legacy format-2 and new
format-3 launches could coexist after reopen, but renewal compared format
versions exactly and could create another format-2 launch beside a live format-3
retry (M5-120; `node.rs:302`, `:4348`, `:4462`, `:15949`). Stale cleanup ignored
failed aborts to removed holders and could erase its owner before those holders
return with staged data (M5-121; `network/p2p.rs:7367`, `:7414`,
`volume.rs:1105`). The corrections preserve verified-only coverage,
directional cross-version ownership, and durable cleanup obligations. M5-122
required focused regressions and the complete local exact-commit gate listed
in TODO.md. That original review ran no builds or runtime checks. M5-114
remains passing historical evidence for `720920d`.

M5-119 through M5-122 passed on exact committed code source
`4880c28fbfce9a1654f970eb11e71d020e938b37` (2026-09-28). Invalid-opening
and invalid-coding findings retain cleanup and retry ownership; a group
retiring before activation completion cannot be recorded as verified coverage.
Format-2 launch renewal yields to valid format-3 ownership or upgrades its
flat-root proof when unowned. Offline removed holders keep durable cleanup
obligations until acknowledged abort. Controlled, real production-worker,
network return and repeated-reopen regressions pass. Formatting, strict locked
all-target workspace Clippy/tests, Docker lab safety and all 23 fresh local
Btrfs/network acceptance invocations passed. The disposable 8 GiB image,
mount, loop, namespaces, interfaces, firewall rules and processes were
independently checked after successful cleanup. That gate closed Milestone 5
on its exact source; exact logs and results are recorded in TODO.md.

The subsequent source-only review of the corrections through `8712ac3`
reopens Milestone 5.
An initial negative verifier finding can finish holder cleanup and remove its
only launch while the production backup waits indefinitely for coverage
(M5-123). Format-2 launch renewal can start a fresh successor before a
same-lane negative activation finishes holder cleanup (M5-124), or yield to
a pending verified activation that later retires without restoring the old
launch's input and retry ownership (M5-125). Removed-holder cleanup obligations
also lack autonomous address discovery after removal when the cached address
is absent or stale (M5-126); the existing return regression injects the live
address manually. Resolve these ownership and discovery paths, then pass
M5-127's focused regressions and complete local exact-source gate. M5-122
remains passing historical evidence for `4880c28`; Milestone 6 waits. This
review ran no builds, tests, daemons or runtime probes.

M5-123 through M5-127 subsequently passed on exact committed code source
`e09a13f8fcdfca1626e04118a668f67e1c4208d9` (2026-09-28). Negative
initial activation and legacy renewal retain a live owner until holder cleanup
completes. A launch that yielded to uncovered activation keeps packed input
and renews onto a distinct group after retirement; eligible retired history
can be forgotten during a running backup when no alternate placement exists.
Removed holders publish signed endpoint-only DHT records so pending aborts can
reach them after address changes. Focused production-worker, return and reopen
regressions passed. Formatting, strict locked all-target workspace Clippy and
tests, Docker lab safety, and all 23 fresh local Btrfs/network acceptance
invocations passed. The disposable image, mount, loop device, namespaces,
interfaces, forwarding, firewall rules and processes matched the baseline
after cleanup. That gate closed Milestone 5 at the time; the source review
below reopens it. Exact evidence is recorded in TODO.md.

The source-only review of the unchanged M5-127 code finds three further
completion blockers. In a normal three- or five-domain full-width placement,
retiring a verified group before activation completion can leave no alternate
parity placement. The new handoff errors after holder cleanup, exits the coding
worker and daemon, and after eligible forgetting the old transcript cannot
reactivate because its attempt receipts were finalized (M5-128). With spare
domains, the handoff may instead pick a full or unreachable parity holder
ahead of a viable one and keep that geometry through retries (M5-129).
An initial invalid-coding transcript also renews with its original coding
coordinator and verifier, allowing repeated attributable failure despite
healthy alternatives (M5-130). Correct these ownership and placement paths,
then pass focused full-width, capacity, negative-evidence and reopen
regressions and the complete exact-source local M5-131 gate in TODO.md.
Milestone 5 is reopened; Milestone 6 waits. M5-127 remains passing historical
evidence for its exact source and exercised cases. This review ran no builds,
tests, daemons or runtime probes.

Source-only follow-up on `7fea0e1` and the current uncommitted replan draft
keeps Milestone 5 open. The committed negative-evidence correction requires two
coordinators outside the old pair, which is impossible in a healthy
three-member guild; the source gate still needs a safe three-domain rotation.
The replan draft is incomplete at source level because it calls an undefined
renewal-options helper and retains old-arity test calls. Its current placement
filter does not address geometry locked into failure retries and expiry
renewal. M5-128 through M5-130 and the exact-source M5-131 gate remain open;
Milestone 6 waits. No builds, tests, daemons or runtime probes were run in this
review.

Source-only follow-up through `ae081a3` supersedes those draft findings: the
renewal helper and call sites exist, retry and expiry can change parity
geometry, and three-member coordinator rotation excludes historically blamed
coders (M5-130). Repeated holder abort now rechecks retired group state after
Forget instead of returning its cached pre-Forget acknowledgement. Committed
three- and five-domain worker regressions cover the full-width retirement,
cleanup, renewal, coverage and reopen path; the new provisioned Btrfs/QUIC
fixture also drives both schedules through backup checkpoint commit and two
reopens (M5-128). Live regressions cover both full and offline first spares,
later usable placement, renewed coverage and reopen (M5-129). Those source
corrections still required the complete exact-source M5-131 workspace,
Docker, Btrfs/network and resource-cleanup gate. At that source-only review,
Milestone 5 remained open and Milestone 6 waited. No builds, tests, daemons or
runtime probes were run in that review.

M5-131 passed on clean exact code source `39a99e7`. The first workspace run
found six restart and cleanup assertions that still expected pre-handoff
behavior; the committed correction checks durable holder obligations,
post-Forget parity removal, successor lineage and cleanup after return. The
corrected tree passed local formatting, strict locked all-target workspace
Clippy and tests, Docker lab safety, and all 24 invocations of the fresh
disposable 8 GiB Btrfs/network acceptance script. Three- and five-domain
full-width backup commit, repeated multi-owner QUIC and five-daemon seed/DHT
recovery passed. The acceptance runner reported cleanup result zero; an
independent audit found the baseline restored for mounts, loops, namespaces,
interfaces, forwarding and firewall rules, with no owned image or process
remaining. All compilation and execution were local, with no remote server.
The exact commands, counts, timings and logs are recorded in TODO.md.
That gate closed Milestone 5 at the time; the source-only review below reopens
it.

Source-only review of that unchanged code reopens Milestone 5. In the
spare-placement retirement path, a holder can acknowledge abort while the old
group is still retained, finalizing attempt receipts but leaving READY parity.
The delegator may then complete activation and create its successor; when the
old group is later forgotten, neither holder deletion nor a second abort is
guaranteed. A group that was added and forgotten between checkpoints also
falls outside the checkpoint garbage-collection inputs (M5-132). Separately,
the required three-member negative-evidence rotation was tested only at the
coordinator-selector level; the live production-worker coverage/reopen test
uses five members (M5-133). Correct the cleanup ownership, add the missing
three-member regression, and pass the exact-source M5-134 gate in TODO.md
before closing Milestone 5. M5-131 remains passing evidence for the cases it
exercised. This review ran no builds, tests, daemons or runtime probes.

M5-132 and M5-133 passed on clean committed code source `a7da0ce`.
Acknowledged abort of a retained group now persists a local holder cleanup
obligation before its attempt receipts are finalized, even when the holder
has not yet received Retire. The cleanup worker waits for that holder's
Forget, then removes old READY parity; a successful local abort at the
delegator preserves the same obligation. The spare-placement regression now
checks real READY parity, successor coverage, delayed holder sync, cleanup and
repeated reopen. The three-member negative-result regression runs the renewed
attempt through production workers to verified checkpoint coverage and two
reopens. Local formatting, strict locked all-target workspace Clippy and
tests, Docker lab safety, and all 24 fresh disposable 8 GiB Btrfs/network
acceptance invocations passed. An independent audit confirmed cleanup of the
owned image, mounts, loop devices, namespaces, links, forwarding, firewall
rules and processes. Exact results and logs are in TODO.md. All builds and
runs were local; no remote server was used. M5-134 closed Milestone 5 at that
time; the source-only review below reopens it.

Source-only review of the unchanged `a7da0ce` code found two cleanup blockers.
An old attempt's post-Forget cleanup deletes READY information by attempt ID
even when a verified successor reuses that same sector; it can leave a stale
volume receipt and remove the successor's readable shard when the source
recipe is unavailable (M5-135). Separately, ordinary lifecycle Retire and
Forget do not create an abort or holder cleanup obligation for a successfully
completed group. Garbage collection considers a redundant group with still-live
sectors live while it is retained, then loses it as an input after Forget, so
its READY parity and receipt can survive later checkpoints (M5-136). Preserve
live information and make every Forget own parity cleanup, then pass the
focused regressions and complete exact-source local M5-137 gate in TODO.md.
Milestone 5 is reopened and Milestone 6 waits. This
review ran no builds, tests, daemons or runtime probes; M5-134 remains passing
historical evidence for `a7da0ce`.

The subsequent source-only review of the uncommitted M5-135/M5-136 changes
found M5-138. A live group's parity can be repaired under a separate repair
attempt ID. The new old-attempt cleanup correctly avoids deleting rows owned
by a different attempt, but it acknowledges the Forget cleanup obligation
while leaving that repaired READY parity and receipt behind. The new historical
GC pass covers forgotten information, not forgotten parity, and the existing
repair regression has to schedule parity GC manually. Finish parity cleanup
for repaired shards while preserving a successor that reuses the group ID,
then run M5-137 on the final committed source. Milestone 5 remains open and
Milestone 6 waits. This review's conclusion is based on source inspection;
M5-134 remains historical gate evidence for `a7da0ce`.

The M5-135/M5-136/M5-138 implementation now retains READY information and its
receipt when an old attempt is cleaned up, pins live and pending successor
information for GC, and creates parity-holder cleanup obligations atomically
with every certified Forget. Cleanup compares READY parity's verified
transcript hash: a repaired shard of the old group is removed with its receipts,
while a successor sharing the group ID keeps its own shard. Focused
source-unavailable successor, completed-group delayed-holder, repaired-parity,
same-ID successor, and repeated-reopen regressions passed locally, as did
strict workspace Clippy. Milestone 5 stays open until M5-137's complete
exact-source local workspace, Docker, disposable Btrfs/network and resource
cleanup gate passes on committed code.

M5-137 passed on clean committed code
`666697aafca6a93cd76c0f54da47c7db4f8edf4a`. The full locked all-target
workspace run passed, including 294 node tests and 11 expected ignored cases;
formatting, strict workspace Clippy and Docker lab safety passed. All 24 fresh
local 8 GiB Btrfs/network acceptance invocations passed, including full-width
and repeated multi-owner QUIC backups and five-daemon seed/DHT recovery over
direct, hole-punched and relay paths. The immediate resource snapshot saw
iptables timestamp/counter changes and veth links still settling after
namespace teardown; a later independent audit confirmed the owned image and
processes gone and mounts, loops, namespaces, links, forwarding and firewall
rules restored to baseline. Exact results and logs are in TODO.md. Compilation
and execution were local, with no remote server. This gate closed Milestone 5
at that time. M5-134 remains historical evidence for `a7da0ce`.

A source-only review of `0000d9d` reopened Milestone 5. A same-ID successor
can stage on another volume, become READY before its active receipt can replace
the old one, and then be stranded when old-attempt cleanup removes the old
object but retains its stale receipt (M5-139). Event-tail catch-up fetches
transcripts only by group ID; after a same-ID re-Add, a lagging peer can use
the successor transcript for the earlier Add and, when it is the successor's
delegator or coding coordinator, schedule an abort of that successor at the
earlier Forget (M5-140). A remote information holder without a local coding
job has no durable pending-plan GC pin between activation and Add, so a queued
candidate can delete its READY information after unrelated checkpoint advances
if no current checkpoint or retained group names that sector (M5-141). Partial
cleanup of repaired parity can delete its object before finalizing the repair
attempt receipt, losing the row from which the current retry path discovers it
(M5-142). Fix these paths, add focused crash/reopen and delayed-event
regressions, and pass the complete exact-source local M5-143 gate before
closing Milestone 5. M5-137 remains passing historical evidence for its tested
source; this review ran no builds, tests, daemons, or runtime probes.

M5-139 through M5-142 are now implemented. Cross-volume activation transfers
the active receipt while retaining old-volume cleanup ownership; cleanup
cannot acknowledge a newer READY copy through a stale receipt. Add events
retain their own verifier transcript for catch-up and Forget, with ambiguous
pre-binding forgotten Adds rejected instead of assigned a successor's attempt.
Remote holders pin verified pending information until Add or terminal cleanup.
Repaired-parity deletion records durable per-attempt retirement before removing
the row, so a later pass can retire its receipt after interruption or offline
volume recovery. Focused regressions, CDDL/transport checks, dynamic recovery,
formatting, strict workspace Clippy, the locked all-target workspace tests,
Docker safety and all 24 fresh disposable Btrfs/network acceptance invocations
passed locally on `8f60298`. An independent audit confirmed resource cleanup
after the immediate snapshot differed only in iptables timestamps and counters.
M5-143 passed and Milestone 5 is closed; exact results and logs are in TODO.md.

The subsequent source-only review of `6606cc1` reopened Milestone 5. Public
volume drain currently migrates only format-1 objects and can retire a volume
with READY variable-profile shards while deleting their receipts (M5-144, now
guarded by refusing retirement while any format-2 object remains).
Seed-only recovery keeps complete event history but retains transcripts only
for live groups, so its recovered node cannot serve a forgotten Add to a
lagging member (M5-145, now corrected). An upgraded pre-binding store similarly loses an
unambiguous old Add transcript when Forget removes the retained fallback
without backfilling its event record (M5-146, now corrected). Event-tail
installation accepted any replay-valid same-group transcript from the first
responding peer because certified Add did not name the verifier attempt
(M5-147, now corrected). Finally,
virtual-zero-only owners activated before Add are omitted from stale abort and
keep durable pending pins (M5-148). M5-148 now avoids those pins, rejects
non-holder activation before mutation, and retires legacy orphan pins during
GC; focused regressions and strict `mb-node` Clippy pass locally. Forget now
also backfills the original event transcript atomically with its cleanup
obligations, and the legacy-store catch-up regression passes through reopen.
Volume drain now retains a readable variable-profile source and receipt rather
than retiring it; its two-volume reopen regression and the volume/store suites
pass locally. Format-2 evacuation remains future work if operators need to
remove a volume before those shards reach terminal cleanup.
Seed recovery now fetches and retains every Add's event-bound transcript;
the recovered-node regression serves forgotten evidence to a lagging member
across reopen, while the dynamic-adoption test and strict Clippy pass locally.
The new Add variant certifies the canonical verifier transcript hash. New
proposal signing requires that binding; installation, catch-up, recovery and
Forget verify it. A distinct appended variant preserves positional Postcard
encoding of historical Adds; a byte-level compatibility test covers old
decoding and hash stability. Same-group, wrong-attempt evidence is rejected
before the correct transcript advances the event, and recovery rejects it.
This protects newly certified format-2 Adds. Format-1 Adds remain unbound:
the installation and recovery hash checks are conditional, so a hostile peer
can still substitute another valid same-group attempt for an old event. This
is M5-150 and blocks closure while old-history catch-up remains supported.
An earlier correction requested fresh signatures from original Add signers,
but source-only review found M5-151: a recovering or lagging original signer
cannot supply its historical evidence, and membership removal can strand the
quorum. The selected fail-closed policy rejects format-1 event-tail catch-up
and requires a preissued certificate for cold recovery; otherwise it requires
trusted assisted recovery. Background migration can create and replicate
those certificates before signer loss. On `04c6d7a`, formatting, strict
workspace Clippy, the locked all-target workspace suite, Docker safety and
every provisioned case before the five-daemon smoke test passed. That smoke
test timed out after 5,400 seconds waiting for its first isolated-topology
backup to commit (M5-152); independent resource cleanup passed. Two
smoke-only reproductions passed in 1,644 and 1,972 seconds on fresh images.
A later workspace rerun found an independent three-domain test fixture reopen
race (M5-153), now corrected. The complete local exact-source gate subsequently
passed on `0c39244`: strict workspace checks, Docker safety, all 24 provisioned
invocations, and independent cleanup (M5-149). A later diagnostic run reached
the isolated backup with all five peers connected, then stalled with verified
activations pending and a common signed Add locked on every member. A debugger
sample found repeated full guild-history replay under the node mutex during
activation selection. M5-152 caches verified membership snapshots by durable
guild state and rebuilds them after events or reopen. The final local gate on
`53ec2ec` passed strict workspace checks, Docker safety, all 24 provisioned
cases, both topology backups and independent cleanup. Milestone 5 is closed;
Milestone 6 may proceed. M5-143 remains passing evidence for its exact prior
source.

The first full M5-114 workspace run on `3e5a7e3` exposed **M5-118**: four
launch-expiry regressions found duplicate same-lane successors. Renewal now
reuses accepted verified activation or a live retry child before an existing
launch, preserving exact signed lineage and atomic input-intent handoff. An
expired durable launch retains cleanup/renewal priority over retry replanning.
All eight focused launch tests now pass, including the four real regressions
with exact successor, capacity/cleanup and checkpoint assertions unchanged.
The controlled retry/activation ownership and repeated-reopen assertions,
strict focused Clippy, formatting and whitespace checks also pass. The first
workspace run had passed formatting, Clippy, 48 core tests and 275 node tests
but stopped at those four failures. The corrected exact source `720920d` then
passed the complete locked workspace gate: formatting, strict all-target
Clippy, all-target tests (48 core, 279 node, 51 store plus CLI/vendor targets),
and Docker lab safety. All 23 fresh disposable Btrfs/network acceptance
invocations passed, including repeated multi-owner QUIC and five-daemon
seed/DHT recovery with direct, DCUtR and relay fallback. Runner cleanup and
an independent resource audit passed. M5-114 closed Milestone 5 at that time;
the source-only review above reopens it. Details and local evidence are in TODO.md.

M5-116/M5-117 implementation update (2026-09-26): durable claims reclaim an
acknowledged child after expiry, staleness or retirement unless terminal cleanup
or accepted submission ownership exists. Live unfenced acknowledgement remains
quiescent. Successor retirement atomically yields to accepted child results or
failures. Cleanup success is distinct from dispatch acknowledgement; neither
missing packed descriptors nor a fence appearing during a delayed acknowledgement
can release cleanup ownership. Exact signed-child terminal metadata prevents
completed histories from reopening, while late parent completion preserves
child-owned retry inputs. Existing signed records and job encodings stay intact.
The remotely placed packed successor regression exercises actual signed expiry,
silent coder/reopen, fresh roles, verifier/activation/checkpoint coverage and
exact holder cleanup. A separate descriptor-less QUIC regression covers a
retirement request followed by coder shutdown before deletion, delayed parent
acknowledgement, an offline volume, delegator-only cleanup after reopen, and
exact zero holder bytes/receipts/reservations through repeated reopen. Controlled
ownership coverage includes accepted child activation/failure and live fenced
acknowledgement. All 17 focused retry tests pass together in 382.28 seconds;
strict locked mb-node/mb-store all-target Clippy, formatting and whitespace
checks pass. Final source inspection finds no remaining implementation blocker
in these corrections. M5-114's full final committed-source local gate remains required;
Milestone 6 waits. Detailed validation outcomes are recorded in TODO.md.

Earlier source-review record:

Latest source-only review (2026-09-26) covers `88898a6..687e207` plus the
pending M5-116 source changes. Acknowledged successor recovery is now present
in the working tree, with priority for accepted child owners and signed-child
terminal metadata. It remains uncommitted and has a new **M5-117 / P2**
blocker: a retirement fence plus absent packed-input descriptors is treated
as completed cleanup. Descriptor-less legacy retries can still have staged
parity or reservations. If the coder stops after retirement is committed but
before holder deletion, the delegator permanently skips its acknowledged
parent and leaks that capacity through reopen. Require explicit successful
cleanup or authenticated ownership transfer before making that history
terminal; gate retirement-before-coder-shutdown with absent descriptors,
interrupted holder cleanup, delegator recovery and exact capacity/receipt
checks. Details and source locations are in TODO.md. Finish M5-116/M5-117,
commit the corrected source, then complete M5-114's full local gate before
Milestone 6. This review ran no builds, tests, daemons or runtime probes;
existing passing results remain historical evidence.

Earlier implementation and review records:

M5-113's packed-input correction now passes focused local validation. Failure
handoff and successor preparation preserve input descriptors atomically; workers
resume successor uploads before delegation and reservations return fresh durable
cursors. Terminal activation/cleanup releases intent, while pending intent pins
the delegator's packed cache against unrelated checkpoint GC. A real production
packed lane passes failure, partial information/parity uploads, offline volume,
coalesced replanning, same-epoch reopen, fresh verification/activation/checkpoint
coverage, exact capacity and repeated cleanup checks. All 13 retry regressions,
durable history, transaction rollback/reopen, cache lifetime, strict locked
mb-node/mb-store all-target Clippy and formatting pass locally. Details and
outcomes are in TODO.md. M5-116 and the complete M5-114 final gate remain open.

The M5-113 implementation audit additionally finds **M5-116**: delegation
acknowledgement marks a retry parent complete, and claims skip it even when its
successor expires silently or needs stale cleanup. No launch owner substitutes
for it. Preserve quiescent live work while making expiry and cleanup reachable,
prefer accepted child evidence, and gate actual acknowledged packed successor
silence, deadline, reopen, fresh activation/checkpoint coverage and cleanup.
Details are in TODO.md. M5-116 must be corrected before the final M5-114 gate.

Implementation update (2026-09-26): M5-111/M5-112/M5-115 corrections now
preserve accepted activation or durably fence cleanup, recognize authenticated
launch-to-retry ownership including redundant owners after crash, and reconcile
retired durable submissions through an uncached authenticated status query.
Existing signed plans, job encodings and peer message discriminants remain
unchanged. Five stale regressions pass, including both arrival orderings,
a second stale job, interrupted/offline cleanup and reopen. The expired
acknowledged failure-arrival regression passes with unrelated coding progress,
live workers, fresh activation/checkpoint coverage, late-result rejection and
repeated reopen. Ownership/history and both transport/CDDL frame regressions,
strict locked mb-node all-target Clippy and formatting pass locally. Detailed
outcomes are in TODO.md. M5-113 still needs durable packed-input intent transfer
and resumable staging before successor delegation; M5-114 still needs the
complete final committed-tree workspace and fresh Btrfs/network acceptance
proof. Milestone 5 remains open and Milestone 6 waits.

Earlier source-review record:

Follow-up source-only review on 2026-09-26 covers `d3fd117` plus the pending
source/protocol changes. Delegator-owned retirement now arbitrates stale launch
and delegated cleanup against accepted verification; expired launch recovery
recognizes an authenticated transfer to retry/activation, and delayed launch
deferral/acknowledgement can yield to that owner. These M5-111/M5-112 changes
and regression sources are still uncommitted and have not been validated by
this review. M5-112's regression must also cover unrelated coding progress.
M5-113 remains a production blocker: packed input intent is deleted on failure
and no successor restaging is performed.

The pending delegated change introduces **M5-115**. A stale durable `Submitting`
job bypasses retirement reconciliation; when the delegator's fence won before
delivery, rejection leaves that job unfinished forever. The claim loop then
repeatedly chooses the same stale job and prevents later stale cleanup, including
after reopen. Reconcile the exact attempt with authenticated delegator evidence,
preserve accepted activation, and complete safely fenced cleanup. Cover both
arrival orderings with a persisted submission job, another stale cleanup job,
offline/interrupted cleanup, worker liveness and repeated reopen. Details and
source locations are in `TODO.md`. Correct M5-115 along with M5-111 through
M5-113 before M5-114's complete final local gate. Milestone 5 remains open and
Milestone 6 waits. This review ran no builds, tests, daemons or runtime probes;
the earlier passing M5-104 record remains historical evidence for its exact tree.

Source-only review of `16c28a5..88898a6` on 2026-09-26 finds three production
P1 blockers. The recent acknowledged-launch ownership, renewal and relay
fixture corrections do not resolve these adjacent cleanup/retry paths:

- **M5-111:** Stale membership cleanup checks verifier evidence before a
  separate awaited epoch read, then discards holders' data without a durable
  retirement fence. A valid historical transcript accepted in between owns
  activation but loses its staged parity, even after an unrelated relabel
  leaves placement valid. Activation and checkpoint coverage remain pending
  through reopen. Arbitrate accepted evidence and retirement before cleanup;
  cover both orderings of result arrival and retirement in launch and delegated
  cleanup, interrupted cleanup, activation/checkpoint completion and reopen.
- **M5-112:** A signed failure arriving after an expired acknowledged claim
  transfers ownership to a durable retry and deletes the launch. Expiry recovery
  still attempts renewal and then deferral against the missing launch. The
  resulting error exits the shared worker and the daemon's main select.
  Reconcile current ownership during fencing/renewal/deferral and gate this
  failure-arrival window while preserving daemon and unrelated-work progress.
- **M5-113:** Signed-failure cleanup removes remotely placed packed inputs and
  acceptance deletes their descriptors. The fresh retry delegates another ID
  without restaging, so a holder without its own source/cache/READY copy cannot
  serve the required input. Retain and transfer input intent, stage the selected
  successor before delegation, and gate a real packed-only remote placement
  through failure, interrupted upload, replanning, activation and reopen.

Exact source evidence and correction requirements are in `TODO.md`. After
these corrections, M5-114 requires source review, focused regressions, the
complete locked workspace and fresh local Btrfs/network acceptance gate on
the final committed tree, and independently verified disposable-resource
cleanup. Milestone 6 waits. This review ran no builds, tests, daemons, runtime
probes, or remote compilation. The earlier passing M5-104 record below remains
historical evidence for its exact source; its fixtures do not inject these
arrival windows or missing packed-input copies.

Previous closure record:

The complete final M5-104 gate passed locally on 2026-09-26 against exact
source `f8e47d34d62a073db6953260571441525dc5e2ac`. Strict locked all-target
workspace Clippy passed in 34.17 seconds. Locked all-target workspace tests
passed every suite, including 48 core, 270 node (10 ignored) and 50 store
(14 ignored), plus all CLI/application and vendored targets. The node suite
finished in 472.87 seconds, covering all recent retry/launch, acknowledged
coordinator-loss, accepted-result expiry, ownership, staging, fairness,
membership and relay/DCUtR regressions. Formatting and Docker lab safety passed.

All 23 fresh local Btrfs/network acceptance invocations passed on the same
unchanged committed source. Repeated multi-owner QUIC finished in 1391.14
seconds; the final five-daemon recovery/transport scenario finished in 3583.56
seconds. Owner and storage-only seed recovery, direct and DCUtR bulk traffic,
and forced-relay bulk fallback passed. The runner exited zero and reported
successful cleanup. Independent checks confirmed the owned mount/image/directory,
loop device, four namespaces, veth interfaces, firewall/NAT rules and test
processes were gone. Exact resources and log locations are recorded in TODO.md
under M5-104. All builds and runs were local; no remote compilation server was
used. Milestone 5 was closed at that point.

Earlier source-review and correction history follows.

Earlier source-only review on 2026-09-26 covers `16c28a5..77c2090` and the
existing uncommitted relay/DCUtR fixture change. No new source blocker was
found in the acknowledged-launch recovery and ownership corrections. Expired
acknowledged work reaches retirement and cleanup; accepted verifier evidence
keeps priority; deferral and same-ID replanning preserve acknowledgement; new
successors use reachable replacement roles while persisted successors retain
their identity and staging intent. The regression sources cover coordinator
loss, expiry/reopen, explicit majority quorum, accepted evidence, and preserved
ownership. The pending relay fixture change explicitly initiates its circuit
and retains the hole-punch, relay-retirement, traffic and fallback assertions.
Milestone 5 is still unfinished: finalize that source change, then complete
M5-104 on the exact committed tree and record disposable-resource cleanup.
Milestone 6 waits. This review ran no builds, tests, daemons, runtime probes,
or remote compilation; earlier validation remains historical evidence.

The subsequent local gate on `77c2090` passed strict Clippy and 48 core tests;
the node suite had 269 passes and one relay/DCUtR fixture failure. Discovery
had established a plain direct session before the intended relay circuit.
The fixture now disables background DHT maintenance for its three initial
nodes and starts a tracked policy dial over the actual circuit before running
the first event loop. This uses the existing transport implementation and
retains the hole-punch, relay-retirement, traffic-accounting and fallback
assertions. The corrected targeted test passes locally in 20.30 seconds.
M5-104 still requires the complete workspace and fresh provisioned gate on
the final committed source; Milestone 6 waits.

Source-only review of `1f3141e..16c28a5` on 2026-09-26 finds M5-110 after
reviewing the launch renewal, staging metadata, fair selection, and restart
regressions. A successful delegation leaves a durable launch marked dispatched.
Claims skip all dispatched current-epoch launches, including expired ones, so
coordinator loss before a result or failure report makes the new expiry recovery
branch unreachable. The pending launch also suppresses lifecycle replanning.
Allow the delegator to fence and clean expired dispatched work, preserving
accepted verifier evidence, and choose reachable replacement coordinators.
Keep signed history immutable and treat silence only as unavailability. Add an
acknowledged-delegation/coordinator-loss regression through same-epoch expiry
and reopen with a configured majority quorum, fresh activation/checkpoint
coverage, late-result rejection, all
holders' capacity/receipt cleanup, and repeated reopen. Exact source evidence
and the correction gate are in `TODO.md`. Milestone 5 remains open for M5-110
and the complete M5-104 local gate; Milestone 6 waits. This review ran no builds,
tests, daemons, runtime probes, or remote compilation.

M5-110's correction now lets expired dispatched launches reach durable cleanup
and renewal. Deferral preserves acknowledgement, and fresh-role selection ranks
reachable authenticated peers while excluding both silent-attempt coordinators.
Existing successors and live replacements retain their immutable identity without
another selection round. Accepted verifier evidence still precedes retirement.
The real QUIC coordinator-loss case passes in 88.95 seconds, covering acknowledged
delegation, partial parity upload, interrupted offline-volume cleanup, same-epoch
reopen under an explicitly configured majority quorum, and fresh activation and
checkpoint coverage with the old coordinator kept offline. Exact signed lineage,
all holders' capacity/receipt cleanup, and two further reopens are checked. The
accepted-result expiry/reopen case also passes. The node lineage case passes in
16.43 seconds, including acknowledgement retention, valid late-result rejection,
and idempotent successor reuse after a crash. The complete final M5-104 local
workspace/provisioned gate remains required; Milestone 6 waits. The first full
workspace run on `4039bd6` passed strict Clippy and 268 node tests, but both new
expiry fixtures outlived their short deadlines during initial dispatch or
verification under suite load. They now allow 120 seconds for setup and then
wait for their unchanged signed deadline before exercising expiry. Production
behavior is unchanged. Rerun the complete gate on the final committed source.
The ownership follow-up also preserves the acknowledgement and explicit
cleanup deferral when the planner proposes the same attempt ID again. The
original signed plan and durable owner remain intact; replanning cannot turn
an acknowledged silent attempt into an undispatched one before retirement.
The lineage regression covers a fresh signed proposal followed by reopen
before fencing, and passes locally in 16.36 seconds. The complete final gate
must include this correction.

Earlier source-only review of `c4e97f8..1f3141e` on 2026-09-26 found two
production-worker blockers after M5-105 through M5-107. M5-108: a durable launch
that outlives its 24-hour deadline is still claimed, but input staging and
delegation reject its immutable expired plan. Same-epoch restart and restored
peers/disks cannot recover it; its pending record also suppresses replanning.
Fence and clean partial/finalized inputs durably, then renew with fresh identity
and current authority while retaining signed history and accepted verifier
evidence. M5-109: launch selection always returns the first undispatched ID,
and staging deferral leaves it eligible, so one offline input destination hides
later runnable launches. Give deferred launches bounded turns, including
delegation and cleanup failures. Required expiry/reopen, two-launch fairness,
activation/checkpoint, and all-holder capacity/receipt regressions are recorded
in `TODO.md`. Milestone 5 remains open; correct both before M5-104's complete
local gate and Milestone 6. This review ran no builds, tests, daemons, runtime
probes, or remote compilation. The following paragraphs retain earlier review
and validation history.

The M5-108/M5-109 correction now durably fences and cleans expired launches,
renews with a fresh signed identity, and atomically links the successor and its
staging intent. Existing live replacements and outstanding cleanup transitions
are reused; retired initial identities cannot be recreated. Input descriptors
survive staging/delegation deferral until terminal activation or failure, while
a hash-bound completion marker avoids redundant staging. Launch claims rotate,
including stale cleanup turns. Accepted verifier evidence is handed to activation
before launch cleanup, including the dispatched-record membership-change case.
New production-worker QUIC regressions cover partial/finalized upload expiry,
interrupted offline-volume cleanup, actual coordinator shutdown after staging,
same-epoch reopen, independent blocked/healthy lanes, exact signed evidence,
activation/checkpoint coverage, aggregate capacity/receipt cleanup on all holders,
and two further reopens. Node coverage proves idempotent successor persistence
and retired-ID replanning. Final focused validation passes: all 17 `retry` tests
in 35.46 seconds and all four `launch_` tests in 69.49 seconds. The complete
committed-source M5-104 gate remains required before closure and Milestone 6.

The earlier complete M5-104 local gate finished successfully on source `1f3141e`:
locked all-target workspace tests (including 264 node passes), strict locked
all-target Clippy, formatting, Docker lab safety, and all 23 fresh disposable
Btrfs/network acceptance invocations passed. The final five-daemon scenario took
1347.19 seconds. Disposable resources were removed and cleanup independently
checked. That result predates M5-108/M5-109 and remains historical evidence;
their final source needs its own complete local gate.

Previously closed on 2026-09-26 after the complete M5-97 gate on corrected source
`c7033fa`. Formatting, locked all-target workspace tests, strict locked
all-target Clippy, Docker lab safety, and the complete fresh disposable
Btrfs/network acceptance script passed locally. The provisioned run used
documentation-only successor `4170dce`; its final five-daemon scenario passed
in 1348.52 seconds. Disposable resources and test daemons were removed.

The closure audit covers variable-profile every-`k` reconstruction, fair stable
slots and multiple roots, authenticated virtual zeros and sparse/large-tree
metrics, delegated coding and sampled transcript replay/attribution, bulk
transfer estimates, membership and retained key/history transitions, current
capacity and crash-safe cleanup/activation/retention, legacy migration and
root/length authentication, encoded-frame limits and aligned upload resume,
and real multi-owner backup, restore, audit/repair, and seed-only recovery.
The corresponding core/node/store regressions passed in the workspace gate;
provisioned filesystem and real-network scenarios passed in M5-97. M5-92
through M5-102's recorded corrections remain implemented. Source-only review
through `515260c` found M5-103 and reopens this milestone; Milestone 6 waits.

M5-103 blocks actual background progress after the proof-identity migration.
The worker claims an incomplete old retry before launches and activations,
then continues even after failure. A retry prepared before downtime is reused
after its deadline and rejected by delegated enqueue indefinitely, even with
all peers online in the same membership epoch. Without a prepared plan, a
three-member guild cannot supply two fresh coordinators after excluding the
old pair, so that retry also monopolizes the worker. The migration regression
queues and directly claims the stronger launch but does not drive this worker.
Preserve signed evidence and safe cleanup while renewing or superseding expired
work and giving deferred retries bounded scheduling turns. Required source
paths and restart/activation/checkpoint regressions are in `TODO.md` M5-103.
M5-104 requires fresh source review and the complete local workspace and
provisioned acceptance gate after correction. This review ran no builds,
tests, daemons, or runtime probes. The records below are history.

The M5-103 correction now visits every worker queue each cycle and rotates
pending retries. It fences late results before cleanup, retains signed expired
plans and failures, and renews with fresh attempt identities, fresh roles, and
current authority. Legacy flat-root retries upgrade to complete-byte format 3;
stronger queued work supersedes compact attempts, and replanning preserves an
existing format-3 retry rather than duplicating its group evidence. Membership
changes also clean prepared uploads. Four real QUIC restart regressions pass
through partial parity upload, verification, activation, checkpoint signing,
cleanup, and repeated reopen. Focused retry tests pass locally; M5-104's
complete workspace and provisioned correction gate is still pending.
Final review also corrected completed old-epoch delegated jobs shadowing
unfinished stale cleanup. Claims skip terminal jobs before authority replay;
a membership-change/reopen regression selects the unfinished upload, releases
its capacity, and leaves both terminal records unclaimed. The initial
acceptance run on `b9aadcc` passed 21 checks before deliberate interruption
for this correction, with all disposable resources removed. M5-104 still
requires a complete gate on the final source.

Source-only review of `515260c..c4e97f8` finds two further blockers. M5-105:
the format-3 coalescing scan treats a same-lane historical retry child as live
work, even after its parent is complete and the child has failed or been
retired. A later valid launch can be suppressed indefinitely by this stale
record. Resolve the live successor or verified coverage while preserving
historical signed evidence. M5-106: production lane queuing uploads inputs
before coalescing selects a different attempt ID, then ignores that returned
plan. The unused ID has no launch or cleanup job; finalized STAGED objects and
receipts can retain capacity across reopen. Resolve the durable attempt before
staging or durably clean unused uploads. Required regressions must exercise
multi-generation retries and the actual production queue, including staged
objects/receipts and used capacity rather than reservation counts alone.
Exact source paths and correction gates are in `TODO.md`. Milestone 5 remains
open; correct M5-105/M5-106 before M5-104 and Milestone 6. This review ran no
builds, tests, daemons, or runtime probes.

The M5-105/M5-106 correction now chooses verified protection or a live retry
successor while skipping failed/retired/expired historical children. New
same-format work safely supersedes blocked retries and retains fresh
coordinator exclusions; preparation rechecks supersession. Production queues
atomically persist a new launch and its separate input-staging intent before
allocating storage. The worker resumes partial staging under the selected
signed ID, records deferrals, and dispatches only after placement succeeds.
Existing positional CBOR launch records and signed history stay unchanged.
Three additional real QUIC regressions cover live-retry replanning, a failed
retry chain with a retired descendant, and an offline partial upload resumed
after reopen. They pass verification, activation, checkpoint signing, staged
receipt/reservation cleanup, exact used-capacity checks on every holder, and
two further reopens. The node regression also checks adverse ordering and
rejected coordinator reuse. All 16 focused `retry` tests pass locally; the
complete final M5-104 workspace/provisioned gate remains pending.

Final source audit also found M5-107: an unused member's relabel discards
accepted verifier evidence despite unchanged valid shard placement, and
epoch-independent initial IDs can collide with retained historical records.
A real QUIC regression reproduced the unwanted second launch after reopen.
The correction preserves replay-verified evidence when current placement is
valid, commits using the current quorum, and keeps invalid-placement cleanup.
New initial IDs bind later membership epochs while retaining epoch-one IDs;
existing live launches/retries coalesce without rewriting signed history.
All 17 focused `retry` tests pass. The exact transcript-preservation regression
passes across two further reopens, the corrected migration regression passes,
and all 48 core tests pass, including epoch-bound identity checks. The complete
final committed-source M5-104 gate remains pending.
The first workspace attempt on `4f8c685` passed 261 node tests and failed two
older assertions that inspected an offline default volume; those assertions
now sum used capacity across all volumes. Milestone 5 remains open and
Milestone 6 waits. All compilation and execution stay local.

M5-36 through M5-44 are implemented, and the complete M5-45 correction gate
passed locally on 2026-09-19. The final committed tree passed formatting,
locked all-target workspace tests, warning-free locked all-target Clippy, and
the full provisioned filesystem/network acceptance script. A later source-only
review found M5-46 through M5-57; their corrections and focused regressions are
implemented. Fresh source review found M5-58 through M5-66 in that correction
series. M5-58 through M5-66 are corrected, and source-only review finds no
remaining blocker in that correction series. The final M5-67 local
workspace/provisioned gate passed on 2026-09-22. Fresh source-only review then
found M5-68 through M5-76. All nine source blockers are corrected, and a
follow-up source-only review finds no remaining implementation blocker.
The complete local M5-77 workspace/provisioned closure gate passed on
2026-09-22. Fresh source-only review on 2026-09-25 found M5-78 through M5-83.
M5-78's persistent fallback regression and M5-83's repeated-roster rollback
regression now pass locally. Source-only review of the later correction series
finds M5-82's stalled-relay gate covered. Later local regressions cover
M5-79's long-history peer requests, M5-80's packed restore and cold shard
recovery with unavailable stale groups, and M5-81's bounded full packing pass.
Fresh source review found no new blocker in the final correction commits. The
complete M5-84 local closure gate passed on `e959d92` on 2026-09-25: formatting,
locked all-target workspace tests and strict Clippy, Docker lab safety, and the
full fresh disposable Btrfs/network acceptance script. A further source-only
review of the same tree found M5-85 through M5-87, reopening Milestone 5;
M5-85 and M5-86 are corrected. Source review of `1e8ee2b` found that M5-87's
coverage-only probe can mark a replacement group covered without proving a
live `k`. Commit `dd5c7e8` corrects that gap and covers both fewer-than-`k`
and any-`k` two-live-sector cases.

The complete M5-88 gate passed locally on 2026-09-25 on source commit
`dd5c7e8`, including the full provisioned Btrfs/network acceptance script.
Further source-only review found M5-89 and M5-90 in the coverage-only cold
recovery path. Their corrections now bind replacement coverage to exact
checkpoint authentication and stop bounded current-group work after sufficient
coverage. The complete M5-91 local workspace/provisioned acceptance gate passed
on source commit `09e9379` on 2026-09-25. M5-88 remains historical evidence
for its earlier tree. Later source-only review found M5-92 through M5-96 in
legacy-root authentication, live-quorum recovery, and restore fallback. The
M5-93 through M5-95 corrections are committed. M5-92 and M5-96 still need a
checkpoint-signing proof that the signed flat root matches the group's full
information bytes even if the revision carries a Merkle commitment. M5-97's
local closure gate remains open; Milestone 6 waits. Commit `c7cc6fd` supplies
that proof in a signed full-byte legacy manifest, and new checkpoint signing
requires its successful replay. Correct legacy revisions without separately
signed Merkle commitments can still use the proof. All M5-92 through M5-96
corrections are implemented. Source-only review of `e64f76e` found M5-98
through M5-100: old durable attempt identities collide with upgraded plans,
existing certified group identities reject stronger transcripts, and the raw
witness bound does not guarantee transportable CBOR frames. Implement and
review those corrections before running the complete M5-97 local gate.
Milestone 5 remains open and Milestone 6 waits.
Those corrections are now implemented. The regression preserves old durable
launch/retry/activation records and both certified groups across restart,
checks historical coverage, and signs a new checkpoint with the stronger proof.
Worst-case witness messages round-trip through the bounded CBOR codec and the
Postcard serializer. M5-97's final local workspace/provisioned gate is pending.
Final source audit of `99c3c82` found M5-101's implicit legacy ciphertext
length gap. Its correction and positive/negative length regressions must also
pass before the complete M5-97 gate closes Milestone 5.
Follow-up source-only review finds M5-102 in `coding_parity_range_bytes`: its
frame-limited result is not rounded to a 16-byte leaf, while holder storage
rejects unaligned upload lengths and offsets. Correct the shared range sizing
used by full-byte staging and delegated encoding, and validate actual writes,
interrupted reservation resume, and finalization at frame-limited geometries.
At that source review, the M5-101 working-tree correction added length checks
to signing, recovery, and audit while preserving explicit packed lengths; it
still needed commit and validation. That review ran no builds or tests.
Subsequent commits `8433c86` and `c7033fa` correct M5-101 and M5-102. Both
focused regressions and the complete local M5-97 gate now pass, closing
Milestone 5.

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
  Current packed inputs use their Merkle root directly. Legacy flat-root plans
  additionally carry complete encrypted information in the manifest to prove
  that the two root representations describe the same bytes. That compatibility
  payload is bounded to 512 KiB per manifest and reported separately as
  `root_binding_bytes`; current production packed plans carry no such payload.
  New full-byte manifests use CBOR byte strings. Before staging, nodes also
  budget both encoded transports, including proofs, event certificates, and
  signed envelopes; untransportable new attempts are rejected. Parity range
  size adapts to the remaining frame space, and event tails return a prefix
  bounded by encoded bytes. Historical transcript replay retains its original
  validation independently of current peer-frame budgets.
- Add versioned variable `k/m` and sector profiles, dynamic membership and event
  tails, quorum policy, writer/key epochs, recovery-key envelopes, rotation and
  revocation. Keep old committed layouts decodable until their retention ends.
- Gate with property tests for any-`k` recovery and packing/layout invariants,
  member add/remove/replacement during interrupted work, key rotation across
  retained revisions, and bounded storage/network amplification.

### Milestone 6 — native Git history, FUSE removal, and native platform backends

Use this decision map when choosing the next implementation slice. These are
requirements of the corrected Git/native-backend roadmap, not completion claims;
`TODO.md` records their current status and remaining blockers.

| Requirement | Plan location and acceptance |
| --- | --- |
| Git-style command frontend and library reuse | Section 1 and this milestone: a separate binary using the daemon's single writer and a maintained Git implementation with native object storage |
| Byte-for-byte files | Sections 3 and 4 and this milestone: raw capture, stage, checkout, recovery, and object exchange; line-ending handling and all content filters stay disabled |
| No second permanent Git payload store | Section 4: native anchors supply blobs; prove native extent sharing and COW isolation |
| Branches and multiple worktrees | Section 4 and this milestone: shared immutable history with separate worktree state and safe optimized checkout |
| Ordinary Git interoperability | This milestone: two-way object/pack exchange and a stock-Git transport bridge, preserving exchanged blob bytes and IDs |
| History pruning that releases data | Section 5 and this milestone: reachability and retention protect live data; durable cleanup releases eligible local anchors and backed-up sectors |
| FUSE removal and production corrections | Section 4 and the R1–R7 queue: remove the withdrawn backend safely and close the non-FUSE integrity, capacity, migration, progress, packaging, and validation gaps |
| Outstanding native platform work | Section 4 and this milestone: finish Windows/macOS backends, metadata, watchers, and application-consistency gates alongside Git work |

Implement the Git pivot through the versioned source-backend boundary alongside
the outstanding original work. The native `.mutualbackup` catalog owns local
history, and the same immutable captured bytes serve backup and Git blobs
without a second persistent payload copy. Git compatibility covers the supported
command syntax and object/pack exchange; our file-content rule stays strictly
byte-for-byte even when stock Git would apply attributes or filters. Guild peers
continue to use the existing signed revision and checkpoint protocol.

At the start of each implementation iteration, reconcile `TODO.md` against all
closure gates below: Git commands, protected graph recovery, ordinary-Git
exchange, physical reclamation, FUSE removal, non-FUSE corrections, native
platform backends, metadata, watchers, and application-consistent capture.
Select an open item whose prerequisites are ready and record its completion
evidence in `TODO.md`.
After each slice, keep every unfinished original item in the queue; completing
the Git command set alone does not finish Milestone 6.

For each command or backend that touches content, verify byte identity through
capture, staging, history, checkout, object exchange, backup, and recovery on
the current source. A line-ending-only edit is a real content change. No
configuration, attribute, filter, or compatibility option may silently convert
it. Apply this gate to Git work and each supported native platform backend,
together with their crash/recovery and native-anchor storage checks.

Track Milestone 6 against these separate closure gates when iterating over this
plan; passing a Git command gate does not close a source-backend or platform gate:

- Version and validate the native source-backend boundary, with byte-exact
  capture/restore and no change to signed peer formats.
- Complete the supported Git command set over native anchors, including
  branches, linked worktrees, protected history, recovery, and two-way ordinary-
  Git object exchange. For each file-touching command, verify that line-ending
  settings and all clean/smudge/process, encoding, and ident rules are inert,
  even if a Git installation or repository enables them by default:
  the captured file, staged blob, exported blob, and restored file have the
  same bytes unless the user or merge operation explicitly changes content.
  Include repositories that configure Git LFS in this check: its pointer bytes
  are ordinary tracked content here, and no filter or external transfer runs.
- Make Git-facing prune release unreachable native anchors and backed-up
  sectors while respecting every live ref, index entry, worktree, protection
  pin, retained signed revision, and in-flight operation.
- Remove FUSE-backed guarded capture and Git integration under R1, including
  the explicit compatibility/export or fail-closed treatment of existing data.
- Close the R2–R7 production corrections with their acceptance evidence;
  existing successful Git command tests do not close these separate gaps.
- Complete Windows and macOS source backends, portable metadata, watchers,
  and application-consistent capture hooks with their platform-specific gates.
  On both platforms, stage and restore mixed-line-ending files byte-for-byte
  through the Git frontend regardless of the host's line-ending defaults.

The Git binary must never opt into Git's automatic CRLF conversion or run a
configured filter, including during import, checkout, merge, or pull. A stock
Git peer may already have converted its own worktree; exchange and preserve its
stored Git blob bytes exactly, without trying to reverse that conversion.
Repositories with conversion rules remain usable: our binary treats those
rules as inert for file bytes rather than rejecting the repository or copying
stock Git's transformed worktree. This rule applies at each Git command gate,
while the original source-backend and platform gates remain separate.
Test line-ending conversion and clean filters independently: Git can normalize
CRLF through `core.autocrlf` or `text`/`eol` attributes without a clean filter,
while a clean filter can change arbitrary bytes. Neither mechanism may run in
our binary, even under inherited system or global Git configuration. This is
an unconditional repository invariant, not a configurable compatibility mode.

Use these concrete acceptance cases throughout implementation:

- Stage files containing CRLF, LF, mixed line endings, no final newline, and
  binary bytes under conversion-inducing Git settings. Assert byte equality
  through capture, blob export, checkout into another worktree, and seed-only
  recovery; compare blob IDs with stock Git's raw `hash-object --no-filters`.
- Change only CRLF to LF in a tracked file. `status` and `diff` must expose the
  change; an explicit `add` and `commit` must retain a different blob, and
  checkout of either commit must restore that commit's exact line endings.
  Also back up that edit without staging it, remove all owner-local source and
  anchor data, and recover from a seed. The working file must retain LF while
  the index and committed blob retain CRLF, with the edit still reported dirty.
- Configure clean, smudge, and process filters that would visibly change bytes
  and record invocation. Exercise supported file-touching commands and verify
  that our binary never invokes them, including during replay after a crash.
- Exchange commits with stock Git in both directions while that client's
  worktree conversions are enabled. Compare stored blob bytes and object IDs
  at the transport boundary; our checkout preserves those bytes, even when
  the external client's worktree has a different presentation.

Keep these byte-policy checks beside native extent-sharing and COW isolation,
reachable-history recovery, and physical-prune
checks. Byte equality alone does not prove efficient storage or safe deletion.

- First extract and version the source-backend boundary from section 4 without
  changing the existing signed peer format. Prove a custom object-store adapter
  over native anchors with a maintained Git library, initially targeting
  SHA-1-format Git repositories for ordinary interoperability. Prefer libgit2's
  custom ODB with a narrow audited Rust FFI adapter; reconsider Gitoxide's
  lower-level components if the prototype cannot meet streaming, safety, or
  storage-amplification gates. Do not implement Git hashing, object encodings,
  or pack parsing ourselves.
- Add the separate Git-compatible local binary for `init`, `add`, `status`,
  `commit`, `log`, `diff`, `branch`, `tag`, `switch`/`checkout`, `restore`/`reset`,
  `merge`, multiple worktrees, `fetch`/`pull`/`push`, explicit `pin`/`unpin`,
  and history `prune`/`gc`. Make the supported subset invocable as `git` through
  an explicit install name or PATH choice. Match basic command and option
  behavior where safe; fail clearly for unsupported Git commands or options
  instead of passing them to stock Git. Implement the supported Git index,
  commit DAG, refs, and safe worktree operations over the daemon's single-writer
  catalog. Stage exact file
  bytes in durable reflink anchors and reflink checkouts on capable same-
  filesystem destinations; explicitly reject unsupported capture backends.
  A requested merge may create new content; capture its exact resulting bytes
  as new blobs, and make conflicts/abort recoverable without normalization.
  Pull and merge from a linked worktree must use that worktree's selected
  branch, index, files, and replayable merge session while sharing the same
  commit graph; other worktrees must remain untouched.
  `restore --staged --worktree` must use one replayable daemon operation for
  the selected paths, so a failed worktree preflight cannot first discard
  their staged bytes.
  Never create a persistent second Git blob or pack copy of native payloads.
- Disable all automatic content conversion in this binary, including CRLF/text
  handling, clean/smudge/process filters, `ident`, and working-tree encodings,
  regardless of inherited Git config, environment overrides, or attribute
  source. Enforce the policy at the source-backend and Git object-store boundary,
  then audit every Git-library call that touches blob or working-tree bytes;
  configuration defaults alone are not the guard. Force those calls onto
  raw-byte paths; never let a Git library's default checkout/filter behavior
  re-enable conversion, including
  during merge with `merge.renormalize`, reset/restore, pull, and
  worktree creation. Reject any command option that requests renormalization
  or a content filter. Import Git blob bytes as raw file bytes and export the
  same bytes. Treat incoming blob bytes as authoritative; do not try to reverse
  conversions already performed by another client's worktree. Treat inherited
  and repository transforming rules as inert for payload bytes, and make this
  behavior visible in help and status when such rules exist. Never run a
  configured filter, `textconv`/external diff, or merge-driver command while
  reading, displaying, or combining tracked content. Define safe support for
  Git file modes, symlinks, and path names rather than silently dropping them.
  Check `status`, `diff`, and dirty-worktree preflight against raw blob bytes,
  so a line-ending-only edit cannot disappear from the index or be silently
  overwritten by checkout, restore, switch, or pull.
  Treat raw-byte behavior as a gate for each supported command, including
  interoperation commands, rather than deferring it to final milestone testing.
  For each file- or blob-touching command, trace the bytes read, the bytes
  hashed/stored, and any bytes written to a worktree or transport. A command
  passes only if its own path preserves those bytes and never invokes a
  Git-library conversion or an external filter; metadata-only commands must
  not introduce a converted payload indirectly.
- Protect the whole reachable Git commit graph and refs as owner-owned backed-up
  content, not just the currently checked-out tree. A signed MutualBackup
  revision/checkpoint is the protection boundary; seed-only recovery must
  reconstruct branches, commits, object mappings, and usable worktrees with no
  local Git catalog. Keep status explicit about commits awaiting backup.
- Implement two-way interoperability through standard Git objects and packs:
  our binary fetches/pulls and pushes against ordinary Git repositories, and
  stock Git can fetch/pull and push through a documented Git transport bridge
  backed by our object store. Do not claim stock Git can open `.mutualbackup`
  directly or require a permanent Git-format payload mirror. Bound transient
  pack space and memory for large and sparse files. The bridge preserves the
  exchanged Git blob bytes and object IDs; a stock Git client's own attributes
  or config may transform its external working tree outside our control.
  Include an explicit existing-repository takeover path in this interop gate:
  preserve imported refs and object IDs, keep `.git` outside native protection,
  and make any raw worktree-versus-Git-blob difference visible before staging.
- Define Git-facing history expiry and prune/GC over refs, index, worktrees,
  retained signed revisions, explicit protection pins, and in-flight work.
  Include the verified direct parent checkpoint's Git graph through the
  one-generation GC grace window: seed recovery may not have installed its
  individual `user-revision` records. Missing parent history fails closed.
  Use retained graphs and exact sector-recipe anchor pins to decide which
  candidates can be deleted; an unrelated pending revision or root cleanup
  must not indefinitely block an older, unprotected blob.
  For remote reclamation, replace a mixed coding group that still supplies
  current packed sectors while retaining expired sectors. Plan the surviving
  sectors against verified coverage from groups containing only current
  information; padding roles do not count as expired data. Keep the old group
  and its READY shards until replacement verification and signed activation,
  then commit Retire/Forget and run durable holder cleanup. Information READY
  objects also obey the ordinary checkpoint-generation GC grace window and
  remain pinned while another live group or in-flight attempt needs them.
  Free wholly obsolete groups before allocating replacement capacity;
  insufficient capacity defers reclamation while retaining current protection.
  Verify deletion through holder storage reads and reconstruct the surviving sector
  from peers after cleanup.
  Exercise this through real Git history as well: remove its last ref or pin,
  advance signed retention checkpoints, prune the native history anchor, and
  verify deletion of the expired raw sectors, packed caches, and READY shards.
  After the information GC grace window and confirmed seed-recovery readiness,
  remove the owner's state and all source/anchor areas again, including any
  stock-Git export used by the test. Recover the surviving graph from peers;
  the expired blob must be absent, current files must be exact, and an unstaged
  edit must survive independently of its unchanged committed Git blob. Keep
  this five-peer QUIC proof distinct from the provisioned five-daemon gate.
  Prune is a real data-deletion operation: once no such protection remains,
  it must release unreachable native anchors, retire their backed-up sectors
  through the existing remote cleanup path, and make the removed history
  unavailable to normal recovery. It must never collect an object still needed
  for a retained revision or live worktree. Reachability is physical as well
  as logical: a live blob ID does not pin every duplicate native anchor.
  Retain anchors named by staged entries and live sector recipes, plus a
  verified source on each filesystem needed for reflink checkout or export;
  reclaim surplus same-content anchors after those pins are accounted for.
  Include
  `pin`, `unpin`, and pin listing in the local command set, and document that
  the current frontend has no implicit reflog retention. Report
  reclaimable logical bytes separately from physically freed shared extents.
- Then validate the already planned native Windows NTFS capture, including VSS
  where appropriate, macOS cloning, platform watchers, portable metadata/ACL
  policy, and explicit application-consistent capture hooks. Each enrolled root
  must pass its complete capture/edit/restore probe; never fall back silently
  to an eager full copy.
- Close the Git phase with a local gate for exact-byte add/edit/commit/checkout
  and multi-worktree cases, asserting captured source = staged blob = committed
  blob = restored file when no edit intervenes, comparing the blob ID with
  `git hash-object --no-filters` on the original bytes, and asserting imported
  and exported blob bytes and IDs remain identical even when a stock Git peer
  has different line-ending or filter settings; mixed LF/CRLF, binary NUL, non-UTF-8
  payloads, and conversion-inducing system/global/repository/environment
  `core.autocrlf`, `core.eol`, `core.safecrlf`, `merge.renormalize`, and
  `filter.<driver>.*` settings and rules from
  `.gitattributes`, `core.attributesFile`, and `.git/info/attributes` for
  `text=auto`, `eol`, `filter`, `ident`, and `working-tree-encoding` across every
  supported byte-touching path: add, rm, commit, status/diff, switch/checkout,
  reset/restore, merge, worktree creation, fetch/pull/push, import/export, and
  prune/GC. Verify a configured filter is never executed, and reject command
  options that enable renormalization or filters without changing index, refs,
  anchors, or worktree. Verify that transforming rules remain present but inert
  while raw-byte commands succeed, including after those rules change between
  staging, commit, checkout, and an ordinary-Git exchange; include a Git LFS
  filter rule and verify that its pointer stays byte-exact without invoking LFS;
  configure external diff/`textconv` and merge drivers and verify raw diff and
  built-in merge results without invoking those commands;
  verify `status` and `diff` report a line-ending-only edit as dirty and
  destructive worktree operations protect that edit;
  sparse and large files; hard links, symlinks, modes, and unusual path names;
  dirty and untracked checkout safety; merge conflicts/abort; crash/reopen at stage,
  ref, checkout, switch, merge, worktree HEAD/index, import, prune, and backup
  transitions; byte-exact branch recovery from a seed after source loss; Btrfs
  extent-sharing assertions for stage and each same-filesystem checkout, COW
  isolation after worktree edits, and physical-deletion measurements; and
  bidirectional stock-Git round trips without a persistent payload mirror.
  Include takeover of a stock-Git worktree whose CRLF file differs from its LF
  blob: the imported blob and object ID remain LF, the worktree remains CRLF
  until an explicit user operation, and no `.git` payload is copied into native
  anchors or backed-up as user files.
- Close each listed platform backend only after its own capture/edit/restore,
  metadata fidelity, application-consistency, source-loss recovery, and raw Git
  add/checkout/interoperability gate under conversion-inducing host settings.
  Milestone 6 closes only after Git, R1–R7 corrections, and the listed native
  platform gates pass.

Use this dependency order for the Git work: versioned source boundary and native
Git object access; byte-exact local history and worktrees; encrypted graph
protection and recovery; ordinary-Git exchange in both directions; reachability-
based expiry and physical reclamation. Execute R1 removal and the non-FUSE
corrections in the section 8 dependency order, alongside native platform work
whose prerequisites are ready. Keep Git byte-policy and crash/recovery checks
in each slice. Milestone 6 closes only when Git, removal, production corrections,
and native platform gates above pass.

### Milestone 7 — release candidate and compatibility freeze

Entry requires the R1–R7 corrections and the revised Milestone 6 gates. FUSE
completion and its canceled bug fixes are excluded. Record supported scale,
platform/filesystem capabilities, Git command/transport limits, and ordinary
Git runtime dependencies in the release contract; existing local Git exchange
does not imply SSH/HTTPS support. Keep package builds distinct from successful
execution of required tests on the release source and artifacts.

- Fuzz every parser and state machine; property-test recovery and authorization;
  test partitions, malicious peers, corruption, remounts, clock changes, huge
  trees, disk/WAL exhaustion, interrupted upgrades, and every incomplete object
  transition. Measure and cap tasks, queues, memory, CPU, connections, relay/DHT
  work, bandwidth, and storage amplification.
- Freeze the documented Git-command subset, byte-exact file policy, Git object
  and transport interoperability, source-backend versions, branch/reflog
  retention, and prune semantics only after cross-version migration and
  source-loss recovery gates pass. Cross-version replay and migration must not
  enable content conversion or silently restage a dirty worktree. Measure both
  logical and physical Btrfs space across add, checkout, branch retention,
  import/export, and prune.
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
Also settle Git format/hash support, ordinary-Git transport compatibility,
byte-preserving attribute policy, source-backend migration, worktree safety,
and history reachability before promising the Git-facing compatibility freeze.

Paged Git validation and retained native restore now use disposable encrypted
SQLite indexes with bounded page caches and per-job database ceilings. Linux
process-kill coverage proves anonymous database/journal cleanup; the durable
restore journal still owns staged filesystem recovery. Linux consumers now pin
the catalog workspace and reserve real anonymous database/journal extents before
writes, preserving configured parity headroom and current checkpoint-copy space
under shared process admission. Physical-limit failure/reopen/retry and Btrfs
rewrite tests pass. Dataset/history quotas, other filesystem writers, scheduling
and cross-platform VFS qualification remain release gates.

Normal current variable checkpoint coverage and variable/packed replacement
planning now stream the completed original-history retained set. Each group
and relevant 600 KiB-bounded witness is read independently; exact live/retired
EOF counts and genesis/current-tip/history fences reject missing, malformed or
extra index rows. Relevant evidence must match the original Add transcript,
not merely a valid group alias. Current writer checks use the indexed latest
epoch and reject rotation/revocation without reviving a historical key.
Checkpoint-head joins are fenced; exact-head legacy sector compatibility and
replacement custody remain intact. Absent/incomplete indexes preserve legacy
access. Historical flat coverage remains on its compatibility validator.

Five new Store/Node fixtures cover complete EOF and lifecycle, damaged/missing/
oversized rows, final tip changes, revoked/latest writer damage, reopen with
unusable flat state, substituted witnesses, expired-input planning and full
root binding. Frozen qualification passes 1,368 distinct tests in 1,372 positive
executions: complete ordinary workspace/all-target drivers plus both provisioned
Btrfs recovery cases, including 396 Store and 537 Node. Format, strict locked
workspace/all-target Clippy, all-target compilation and four debug builds pass.
Evidence: `/tmp/mb-m6-streamed-coverage-final-fhxnz87b`. Tests run sequentially by
target with unchanged deadlines. The completed scan's work and request vector
still need paged admission; event ingestion/bulk lifecycle and the complete
shared quota/ownership/activation/production/retention/seed path remain open.
121 other ignored cases and fresh installed qualification remain open. Dense
1 TiB and native Windows/macOS qualification remain user-deferred.

Independent source/binary/test-inventory and native/preservation audits pass.
Retiring only the superseded debug archive and preliminary/failed Node drivers
reclaims 11.44 GiB, leaving 47.28 GiB in `target`; current qualified executables,
29 older archived paths, 14 auxiliary WIP files and all 10 installed roots stay
intact. Original diagnostic evidence remains available. The post-commit audit
checks exact Git-tree bytes against qualified code and verifies preservation.

Both public paged checkpoint layouts now acquire local private/bootstrap/source
and READY custody through a resumable walk under their original enclosing
metadata owner. One 1,024-byte journal binds the original certificate/header,
independent trust, holder and indexed cursors. Each call visits one revision or
one bounded coding group, checks the actual assigned holder and full local
bytes, and publishes progress only after event/predecessor and exact owner
checks inside a CAS writer. Cursor/scan work shares the existing cumulative
private/payload/proof budget. Failure preserves acquired pins and the cursor;
replay reauthenticates dependencies, and cancellation invalidates completion
atomically before the existing one-dependency retirement steps.

Completion verifies every declared revision and coding EOF and exact owned
private/payload counts, including holders with no local assignments. Logical
revision ownership and physical shard placement are independent. Local legacy
private revisions require their original ownership bridge; group/revision IDs
and existing migration guards remain intact. Complete local acquisition does
not publish a current or distributed protected checkpoint. Fixed legacy
bridges, distributed readiness/activation, all metadata/WAL/index/scratch and
physical quotas, normal production/retention/seed recovery, historical flat
validation and remaining bulk lifecycle integration remain open. Normal paged
producers stay disabled.

Four new Store and two new Node fixtures cover original owners, missing READY
roles, exact EOF after lost rows, restart, sharing, admission, damaged records,
actor substitution and actual-current changes at insertion, advancement and
cancellation. Node supplies all assigned original groups and completes after
reopen with unusable flat state. Frozen format, strict locked workspace/all-
target Clippy, all-target compilation, four debug programs, complete ordinary
workspace and both provisioned Btrfs recovery cases pass: 1,374 distinct tests
in 1,380 executions, including 400 Store and 539 Node. Evidence: `/tmp/mb-m6-local-checkpoint-custody-rh5db6gq`.
Targets run sequentially with four test threads and unchanged deadlines.
121 other ignored cases and fresh installed-artifact qualification remain open;
dense 1 TiB and native Windows/macOS qualification remain user-deferred.

Initial Store assertions incorrectly expected the private logical owner to
hold READY shards; the fixture places those shards on other holders. An initial
Node extension staged only one of the fixture's two assigned groups, and the
new full-custody walk correctly rejected its missing READY role. Dedicated
final fixtures provision all assignments; existing migration tests retain their
original behavior. These initial logs and a corrected Clippy style finding
remain separate from the accepted frozen passing inventory. No production
bounds, authorization checks or test deadlines were weakened.

Independent frozen source/binary/exact inventory, native-cleanup and preservation
audits pass. Retiring exactly the superseded `515d1af` debug archive reclaims
9.35 GiB and leaves 47.39 GiB allocated in `target`. Current
qualified executables, 29 older archived paths, 14 auxiliary uncommitted files
and all 10 installed roots are preserved. The post-commit Git-tree/code/binary
and preservation audit binds the qualification to the committed source.

### 2026-10-11 — Original legacy private custody under paged checkpoints

Bind existing retained legacy private conversions to their original checkpoint identities in both public layouts. Keep the original signed legacy body and revision ID; borrow the separately published conversion, bootstrap and native/source pins. Paired 1,024-byte dependencies bind the complete original reference, converted bundle and active migration journal fingerprint. An independently updated 32-byte pin count prevents a damaged last backlink from permitting cancellation. Checkpoint and journal cancellation remain serialized with acquisition and bounded retirement. Shared admission includes legacy body reads, journal/private/bootstrap custody and all dependency/counter rows; complete local custody counts paged and legacy dependencies separately.

Two new Node fixtures use real authenticated legacy metadata and provision every original local information assignment. They cover original body preservation, complete EOF, replay/reopen with unusable flat state, shared owners, missing paired and last reverse pins, oversized journals, actor binding, budget refusal and actual-current changes during acquisition and retirement. Existing migration data/Git and native cases remain part of full qualification. The bridge is local acquisition; fixed legacy groups, full legacy migration authority integration, distributed availability/current activation, full quotas/admission, normal production and seed-only recovery remain open. Normal paged producers remain disabled. Hardware qualification remains user-deferred.

Preliminary logs are separate: a mutable test binding was corrected at compile time; the first runtime fixture lacked the mandatory format-three Merkle migration authority and correctly failed before bridge acquisition. Final fixtures use the existing signed-Merkle format. No production authority, bounds or test deadlines were weakened.

Frozen formatting, strict locked workspace/all-target Clippy, all-target
compilation, four debug programs, the complete ordinary workspace and both
provisioned Btrfs recovery cases pass: 1,376 distinct tests
in 1,378 executions, including 400 Store and 541 Node.
Evidence: `/tmp/mb-m6-legacy-private-custody-p0cko6en`. Targets run sequentially with four test threads
and unchanged deadlines. The original 32 MiB per-legacy-envelope bound remains
in force; this bridge does not claim paged fairness for legacy envelopes.
121 other ignored cases and fresh installed-artifact qualification remain open;
dense 1 TiB and native Windows/macOS qualification remain user-deferred.

Independent source/binary/exact-inventory, native-cleanup and preservation audits
pass. Exact retirement of the superseded `7dcc284` debug archive and the
preliminary Node-only executable reclaims 10.42 GiB and leaves
47.40 GiB allocated in `target`. Current qualified executables, 29 older
archived paths, 14 auxiliary WIP files and all 10 installed roots are preserved.
The post-commit audit binds the qualified code and executable inventory to the
committed tree. Complete enclosing activation, fixed legacy migration, full
metadata/WAL/index/scratch/traversal and physical quotas, normal producers and
seed-only recovery, remaining bulk consumers and the R5/R7 gates remain open.

### 2026-10-11 — Bounded original-history normal event admission

Normal proposal signing, signature collection and event installation use the complete durable original-history index. Unsigned proposal validation runs the same non-membership rules and original verifier evidence in a disposable bounded overlay; its opaque point-row guard has no installation capability. Original quorum verification remains mandatory for publication. Signing guards the exact indexed rows and original current authority before and after its serialized write; signature collection fences its exact previously validated lock/current scope and reads bounded journals. Original events, event-bound transcripts, membership projections, cleanup obligations, partial-signature deletion and audit invalidation publish atomically.

Indexed installs no longer rewrite or materialize the complete DynamicGuildState. The explicit compatibility API reconstructs the full value from every bounded original event under genesis, tip, full-tail and original-history fences, using a coherent read snapshot on independent readers. Older absent/incomplete indexes retain their validated legacy path and explicit one-event catch-up; malformed or conflicting indexes fail closed. Full-value compatibility consumers and event-tail replay still allocate growing history and remain integration work. This does not derive the final metadata budget, enable normal paged producers or complete enclosing checkpoint availability/current activation.

Three new Node tests exercise real normal admission with an unusable 2 MiB cache: writer/recovery key rotation and revocation, removed-member refusal, partial signatures, unchanged original bytes, idempotent replay/reopen, original coding Add witness binding, refused unsigned installs, Retire/Forget deadlines, and actual authority/selected indexed-row changes during signature writes. Existing legacy-store fixtures explicitly save a complete old-format state before removing the index; fault targets follow the original rows now written. Preliminary old-cache expectations and the raw decoder-versus-state-validation mismatch remain in separate diagnostic logs. No production authorization, bounds or runtime test deadlines were weakened.

An earlier workspace attempt was stopped before Node after identifying an obsolete full-value cache assertion outside the authority preflight. Its source/binary/native cleanup checks pass, but its incomplete inventory is excluded. The final compatibility test checks reconstruction from original events and refusal after an original event is changed.

Frozen formatting, strict locked workspace/all-target Clippy, all-target
compilation, four debug programs, the complete ordinary workspace and both
provisioned Btrfs recovery cases pass: 1,379 distinct tests
in 1,383 executions, including 194 Core, 400 Store, 117 Git and
544 Node. Evidence: `/tmp/mb-m6-indexed-event-admission-final-8hn_aomd`. Targets run sequentially with four test threads and
unchanged deadlines. The per-event envelope/point-row/evidence admission is not
a 25 ms fairness qualification or the final retained metadata/SQL/WAL policy.
121 other ignored cases and fresh installed-artifact qualification remain open;
dense 1 TiB and native Windows/macOS qualification remain user-deferred.

Independent source/binary/exact-inventory, native-cleanup and preservation audits
pass. Exact retirement of the superseded `2c3e86e` debug archive and preliminary
Node-only executable reclaims 10.43 GiB and leaves 47.41 GiB in
`target`. All current qualified executables, 29 older archived paths, 14 auxiliary
WIP files and 10 installed roots are preserved. The post-commit audit binds the
qualification to the committed tree. Full-value compatibility/event-tail replay
and remaining bulk consumers, complete metadata and physical admission, enclosing
availability/current activation, fixed legacy migration, normal producers and
seed-only recovery, historical topology/signature cause/full matrix and remaining
R7 software/release gates remain open.

### 2026-10-11 — Preserve supported bulk SQL admission

The existing single-owner allocator maps three dense 64 KiB sources to four
64 KiB packed sectors. A supported 384 MiB source batch therefore already has
512 MiB of packed payload before serialized records, keys, indexes and journal
framing. Normal legacy packed-cache publication uses one `put_records_iter`
writer across the complete batch. A buffer/RSS budget is not a bound on that
transaction or on inherited WAL retained by an independent reader. An attempted
unconditional 512 MiB journal cap was withdrawn before commit; it would narrow
existing supported operations. Its source/logs remain separate diagnostic
material under `/tmp/mb-m6-sql-journal-limits-xz2xgzgj`; the incomplete attempt is
not accepted qualification.

The new explicit Linux Store regression streams 8,193 64 KiB values without
materializing the batch, rolls back a producer failure after all values, keeps
the reader's original snapshot, then commits, reopens and verifies complete EOF
from the inherited WAL before checkpoint/reopen. Frozen execution uses
531.40 MiB WAL and 18.64 MiB peak process RSS. This is the existing generic
atomic writer contract, not a complete packing/capture/recovery, enclosing quota
or dense 1 TiB qualification. Production behavior and admission limits are
unchanged. The enclosing policy still must derive all original/private/source/
bootstrap/history/owner records, control/parity tables and indexes, unreclaimed
main pages, WAL/SHM/rollback journals, encrypted scratch and checkpoint copies,
and source/packing/information/parity allocation across shared physical domains.
Declared retained-history/job/count limits and bounded publication must preserve
supported geometry and original identities before producers can be enabled.

Frozen qualification passes 1,380 distinct tests in
1,380 executions across all 19 ordinary workspace drivers,
the explicit bulk case and both provisioned Btrfs recovery cases: 194 Core,
400 ordinary Store, 117 Git and 544 Node. Formatting, strict locked workspace/
all-targets Clippy, test compilation and four debug program builds pass. Evidence:
`/tmp/mb-m6-bulk-journal-admission-thz39kz6`. Independent source/binary/exact-inventory, memory,
native cleanup and preservation audits pass. Exact retirement reclaims
8.89 GiB and leaves 47.41 GiB in `target`; current executables,
eight unchanged shared inodes, 29 older archived paths, 14 auxiliary WIP files
and all 10 installed roots remain intact. The post-commit audit binds the
qualification to the committed tree. 121 other ignored cases and fresh installed
qualification remain open. Complete R3 policy, distributed availability/current
activation, fixed legacy coding and remaining bulk consumers, normal paged
production/retention/seed recovery and R1/R5/R7 software requirements remain open.
Dense 1 TiB and native Windows/macOS gates remain user-deferred.

### All-table logical database admission (2026-10-11)

An explicitly declared DatabaseRecordQuota covers all seven Control tables and
all three Parity tables: metadata, every protocol kind, operations, checkpoint
locks/heads/pages, recovery shards, staged/ready parity, acknowledgements and
preallocated coding reservations. Accounted bytes charge stored text/BLOB byte
lengths, eight bytes per integer and primary-index locator, duplicated
primary-key bytes, a possible partial-index key reserved for every protocol
row, a 32-byte row charge, and a 1 KiB counter/guard reservation. This
definition does not bound SQL schema text, database/index page allocation, WAL,
journals, scratch, filesystem allocation or traversal work.

Persistent AFTER triggers account only actual writes, including existing open
connections. INSERT, UPDATE, DELETE and REPLACE participate in the enclosing
SQL transaction; quota failure rolls back a streamed batch. Guarded exact
readback rejects ignored/reverted counters, changed limits and tampered guard
values. Incremental BLOB writes use previously charged fixed-length
reservations.

New stores and legacy stores remain unconfigured until local policy explicitly
requests adoption. An IMMEDIATE transaction installs the canonical tables,
triggers and cursor. Adoption freezes ordinary writes and advances at most 128
row-length headers per transaction across every table using native byte-length
queries that do not materialize large text/BLOB cells, including negative
rowids. It resumes across reopen, charges original data without rewriting it,
and reaches ACTIVE only at every table's EOF. Incomplete adoption can be
aborted; an active quota can be resized within current usage. Read-only and
writable openers reject incomplete/malformed trigger schemas or missing
accounting.

Node exposes explicit control and per-volume policy entry points, resumes an
interrupted adoption before startup reconciliation, and aborts a newly refused
adoption without leaving normal writes frozen. Existing scopes for page and
retained-source quotas continue to apply. Both provisioned native migration and
source-loss recovery fixtures exercise declared all-table quotas. The existing
8,193 x 64 KiB atomic-writer regression now runs under a declared 1 GiB logical
quota, preserving supported writes whose committed WAL exceeds 512 MiB.

Frozen qualification passes 1,392 distinct tests: 194 Core, 409 ordinary Store,
117 Git, 547 Node, the explicit bulk case and both provisioned Btrfs recovery
cases, plus the remaining workspace targets. Format, strict locked
workspace/all-targets Clippy, compilation and all four debug builds pass. The
large batch uses 531.41 MiB committed WAL and 26.68 MiB peak process RSS under
its declared quota. All 330 frozen inputs, 327 code/dependency inputs and 23
exact executables are audited. 121 other ignored cases remain unexecuted. Exact
superseded-inode retirement reclaims 9.95 GiB; target uses 47.42 GiB. Current
binaries/aliases, 8 unchanged shared inodes, 29 older archived paths, 14
auxiliary WIP files and 10 installed roots are preserved. Evidence:
`/tmp/mb-m6-all-record-quota-final-0r1ucce3`.

This component is logical data/index-key admission, not the complete R3 single-
owner upper bound. The full enclosing metadata, SQL/index/WAL/scratch/traversal
and physical policy, distributed readiness/current ownership, complete legacy
joins, normal paged producers/retention/seed recovery, R5 and fresh installed
R7 qualification remain open. Normal paged producers remain disabled. The real
dense 1 TiB and native Windows/macOS gates remain user-deferred.

Retained packing construction now binds original complete source authority to
reserved page ownership, durable planned attempts and exact physical output
loans. Local completion preserves the whole original directory and dependencies
through reopen; cancellation fences all three children without deleting data.
Private temporary storage identities preserve public sector/coding IDs and
coexisting final role 0. Ten Store and one real Node regressions pass within
1,510 frozen qualified cases, with 366-input/23-executable audits and
four provisioned Linux native fixtures. Retirement reclaims 10.75 GiB;
target uses 48.62 GiB. Complete source custody, aggregate single-owner
admission/quotas, bounded cleanup, coding/activation, normal retention/seed
recovery, legacy consumers and R5/R7 remain open. Normal producers stay disabled
and hardware gates remain user-deferred. Evidence: `/tmp/mb-m6-packing-operation-q30xcx8b`; see ADR 0002.

Cancelled packing output now retires through an indexed exact-attempt step.
Original physical bindings, pending/checkpoint/READY/migration owners and
conditional plan/output/counter updates preserve offline and interrupted
cleanup. Missing pre-loan locators use admitted exact lookups; unrelated legacy
records are not scanned. Reopen resumes physical success followed by control
rollback. Six Store and four real-volume cases plus the updated actual Node
fixture pass within 1,520 frozen qualification tests on 368 inputs and 23
executables. Retirement reclaims 9.46 GiB; target uses 48.61 GiB.
Physical compaction, aggregate admission/quotas, complete source/coding/
checkpoint integration, normal retention/seed recovery, legacy consumers and
R5/R7 remain open. Producers stay disabled and hardware remains user-deferred.
Evidence: `/tmp/mb-m6-packing-cleanup-q_bm7yfn`; see ADR 0002.

Original paged packing inputs now join exact retained catalog loans under the
producer writer, preserving bootstrap/data/private-page identities and shared
owners. The actual native fixture combines the unchanged legacy base with a
retained paged candidate, rejects missing loans before reads, packs real volume
outputs, reopens after working-tree loss and cancels through indexed cleanup.
Two new Store cases, 25 focused ordinary cases and the extended 581.15-second
native case pass within 1,522 frozen qualification cases on 368 inputs and 23
executables. Retirement reclaims 9.45 GiB; target uses 48.61 GiB.
All-format input custody, aggregate admission/quotas, coding/checkpoint
availability/activation, normal retention/seed recovery, legacy consumers and
R5/R7 remain open. Producers stay disabled and hardware stays user-deferred.
Evidence: `/tmp/mb-m6-packing-input-join-bwnl73w8`; see ADR 0002.

Retained packing outputs now enter the existing signed coding-information
upload lifecycle through exact completed proof/output/loan and original root
joins, current checkpoint/capacity/indexed event fences and bounded ciphertext
verification. The real fixture retries receipt publication and reopen, activates
through the original transcript verifier, then removes temporary outputs while
preserving final READY information. Two new Store cases and 34 focused cases
pass within a 1,524-case qualification on 368 inputs and 23 executables: 695
fresh runs and 829 exact unchanged cases reused with source and binary guards.
Retirement
reclaims 9.46 GiB; target uses 49.71 GiB. Complete enclosing checkpoint
and distributed integration, aggregate admission/quotas, normal retention/seed
recovery, legacy consumers and R5/R7 remain open. Producers stay disabled and
hardware stays user-deferred. Evidence: `/tmp/mb-m6-packing-coding-transfer-length-fe8xouxc`; see ADR 0002.

Both original paged checkpoint layouts now support durable root-authenticated
revision/order/group lookup under the exact retained owner. Locator rows and a
complete independent traversal share enclosing custody admission; partial
indices stay unreadable, retry survives reopen and cancelled cleanup preserves
shared owners. Node lists bounded retained snapshot pages without current-head
activation. Seven Store regressions and the extended real directory fixture
pass within 1,531 qualified cases: 1,468 fresh and 63 exact unchanged reused.
Format, strict Clippy, four builds, four Linux native fixtures and
370-input/23-executable audits pass. 121 ignored cases remain unexecuted.
Normal current listing/restore, distributed activation, aggregate admission/
physical quotas, normal retention/seed recovery, legacy consumers and R5/R7
remain open. Producers stay disabled; dense 1 TiB and Windows/macOS hosts stay
user-deferred. Evidence: `/tmp/mb-m6-checkpoint-lookup-xwm57bjj`; see ADR 0002.

Exact superseded-inode retirement reclaims 9.47 GiB; target uses 49.73 GiB. Current executables, 29 older archived paths, both failed Node artifacts, 14 auxiliary WIP files and all 10 installed roots remain intact.

Exact native snapshot restoration now consumes both original retained checkpoint
layouts, preserving original legacy IDs through independently retained
conversions. Final output publication checks exact original private custody
under one short writer; data I/O stays outside it. Checkpoint-bound operation
identity prevents foreign adoption, while the complete durable Publishing inode
finishes after source/checkpoint retirement without original reads. Two Node
cases, both legacy fixtures and the real native data failure/reopen fixture
pass within 1,533 qualified cases: 1,260 fresh and 273 exact unchanged reused.
Format, strict Clippy, four builds, four Linux native fixtures and
371-input/23-executable audits pass. 121 ignored cases remain unexecuted.
Paged Git installation, normal current listing/restore, distributed checkpoint
activation, aggregate admission/physical quotas, normal production/retention/
seed recovery, legacy consumers and R5/R7 remain open. Producers stay disabled;
dense 1 TiB and Windows/macOS hardware stays user-deferred. Evidence:
`/tmp/mb-m6-checkpoint-restore-7o2i3ix5`; see ADR 0002.

Exact superseded-inode retirement reclaims 9.48 GiB; target uses 49.73 GiB.
Current executables, 29 older archived paths, both failed Node artifacts, 14
auxiliary WIP files and all 10 installed roots remain intact.

Ordinary Git history, proposal and status metadata now uses a complete verified
encrypted index and on-demand ODB reads, preserving original v1 identities and
supporting exact overlays without a whole historical metadata array or memory-
backend copy. The index outlives its source/loader through C ownership; SQL
callbacks serialize the movable scratch owner and preserve final cleanup.
Four new ordinary cases and ten focused history cases pass. The explicit
1,027-object/512.5 MiB metadata corpus uses 23.10 MiB peak RSS for short history,
status and identity enumeration. Full qualification passes 1,538 cases: 1,265
fresh and 273 exact unchanged reused, with strict Clippy, builds, both bulk
cases, four Linux native fixtures and 372-input/23-executable audits. 121 ignored
cases remain unexecuted. Ordinary Git takes 243.74s against the prior 112.15s,
reflecting encrypted disk work in place of whole-history memory copies.
Full paged Git installation/consumers, aggregate admission/physical quotas,
distributed activation, normal paged production/retention/seed recovery, legacy
consumers and R5/R7 remain open. Producers stay disabled; dense 1 TiB and
Windows/macOS hardware stay deferred. Evidence:
`/tmp/mb-m6-git-metadata-odb-m0x4r7kv`; see ADR 0002.

Exact superseded-inode retirement reclaims 9.49 GiB; target uses 49.92 GiB.
Current executables, 29 older archived paths, both failed Node artifacts, the
failed Git fixture, 14 auxiliary WIP files and all 10 installed roots remain
intact.

Original paged Git metadata now retains immutable v2 headers and 32 KiB
fragments, preserving original OIDs under the completed catalog owner. Typed
EOF, same-writer empty/exact-retry checks and exact readback fence publication.
Both legacy and paged metadata use bounded encrypted ODB fragments and C read
streams; large streaming does not widen legacy whole-object or collected-ID
limits. Preserved inventory verifies the full namespace and remains read-only.
Five new Git regressions pass, including an object above 64 MiB. Qualification
passes 1,543 cases: 760 fresh and 783 exact unchanged reused, with strict Clippy,
builds, both bulk cases, four Linux native fixtures and 373-input/23-executable
audits. The 512.5 MiB corpus uses 22.93 MiB peak RSS; 121 ignored cases remain
unexecuted. Verified retirement reclaims 9.77 GiB; target uses 50.12 GiB.
Current artifacts, older saved evidence, auxiliary WIP and installed roots remain
intact. Full refs/blob installation and normal paged graph consumers, aggregate
admission/physical quotas, distributed activation, normal production/retention/
seed recovery, legacy consumers and R5/R7 remain open. Producers stay disabled;
dense 1 TiB and Windows/macOS hardware stay deferred. Evidence:
`/tmp/mb-m6-git-metadata-chunks-p158blav`; see ADR 0002.

Complete paged Git catalogs now install exact metadata, refs, verified native
blob mappings, the selected branch and a clean HEAD index without collecting
historical objects or output rows. Private encrypted staging and complete graph/
plaintext validation precede the destination writer. Disk-backed HEAD expansion
preserves shared paths, raw names and modes. Atomic checked publication fences
late competing writes and ignored rows; completed retries preserve changed or
deleted user rows by rejecting them. Scratch uses registered catalog filesystem
capabilities/WAL reservations, or the Node consumer's admitted private index.
Five ordinary regressions and the explicit 1,027-object/>512 MiB full-import
corpus pass. Frozen qualification passes 1,549 cases: 766 fresh and 783 exact
unchanged reused, with strict Clippy, builds, three bulk gates, four Linux native
fixtures and 374-input/23-executable audits. Full import uses 23.35 MiB peak
RSS; 121 ignored cases remain unexecuted. The initially incorrect procfs fixture
is corrected and its failed source/log/binary preserved. Verified retirement
reclaims 9.50 GiB; target uses 50.30 GiB. Current artifacts, older evidence,
auxiliary WIP and installed roots remain intact. Checkpoint-bound blob recovery/
custody transfer, normal paged graph/ref/blob consumers, aggregate admission/
physical quotas, distributed activation, normal production/retention/seed
recovery, legacy consumers and R5/R7 remain open. Producers stay disabled; dense
1 TiB and Windows/macOS hardware stay deferred. Evidence:
`/tmp/mb-m6-paged-git-install-gbaalutb`; see ADR 0002.


Complete retained native/Git restore (2026-10-14):
The Linux full restore API installs original paged Git history and recovered
blob anchors inside the durable inode-owned staging tree. Format-4 jobs retain
a distinct identity from native-only format-3 jobs. Final custody publication
continues to use the original retained checkpoint writer; completed Publishing
jobs may finish after source retirement. Root metadata applies after Git
installation, and future anchor location hints survive the final rename. The
public default Git importer now obtains scratch from its real registered
directory capability. Tests cover both checkpoint layouts, stable authenticated
local data sources, original raw paths, sparse bytes, Git history/status, fault
rollback, reopen and source-free publication replay. Frozen qualification
passes 1,552 distinct cases: 769 fresh and 783 exact
unchanged reused. All 573 ordinary Node and 131 ordinary Git cases pass, along
with four provisioned Linux native cases and the three bulk gates. Formatting,
strict locked workspace/all-target Clippy, builds and source/binary preservation
checks pass. The >512 MiB Git import peaks at 22.45 MiB RSS; metadata ODB peaks
at 22.77 MiB. There are 121 unexecuted ignored cases. Both failed fixture
attempts retain their exact source, log and binary. Remote packed-shard
reconstruction, seed-only orchestration, aggregate quotas, normal producers and
remaining Milestone 6 gates stay open. Hardware qualification stays deferred.
Independent audit verifies 375 inputs and 23 qualified executables.
Exact superseded-binary retirement reclaims 9.51 GiB; target uses 52.47 GiB.
Current binaries, older qualified/failed evidence, 14 auxiliary WIP files
and all 10 installed roots remain preserved.
Evidence: `/tmp/mb-m6-paged-git-restore-iz6u03oj`.

Retained packed-source recovery (2026-10-14):
The exact retained checkpoint can now retain recovery locators from its complete
original packing/coding proof. Batches contain at most 64 rows. A bounded cursor
binds the original header/certificate/trust and complete chunk EOF; all declared
locator debt is charged before copying. Retries verify original rows and reject
missing or substituted completed entries. Cancellation fences use, and bounded
retirement preserves shared owners. Locator rows supply no byte authority.
Linux native/full restore falls back to original root-authenticated coding
witnesses and retained local READY roles, reconstructs missing information and
checks original packed Merkle/legacy byte roots plus the complete signed source
Merkle and byte roots before decryption. One source and one bounded codeword
remain live; witness/payload work share an admitted per-source envelope. Both
checkpoint layouts pass parity-only source-loss restore, slot substitution,
missing-role, publication faults, cancellation, capture retirement and reopen
fixtures; two Store cases cover index rollback/retry/reopen and shared retirement.
Remote peer transport, seed/private bootstrap orchestration, complete operation
admission/physical quotas, normal producers/distributed activation and remaining
M6 gates remain open. Dense 1 TiB/native Windows/macOS hardware remains deferred.
Frozen qualification passes 1,554 distinct cases: 1,281 fresh and 273
exact unchanged reused. All 511 ordinary Store, 573 Node and 131 Git
cases pass, along with four provisioned Linux native cases and three bulk
gates. Format, strict locked all-target workspace Clippy, builds, frozen
source/binary checks and native cleanup pass. Full Git import peaks at
22.09 MiB RSS; metadata ODB peaks at 23.44 MiB. There are 121 unexecuted
ignored cases. Independent audit verifies 377 inputs and 23 executables.
Exact superseded-binary retirement reclaims 8.82 GiB; target uses
52.49 GiB. Current binaries, failed/older qualified evidence, 14 auxiliary
WIP files and all 10 installed roots remain preserved. Evidence:
`/tmp/mb-m6-retained-packed-recovery-_48f21xm`.

Exact retained peer restore (2026-10-14):
A dedicated restore session retains the original directory lease, keys and
writable job connection. Existing Node APIs keep their original writer and
format-3/4 identities. Peer work uses the independent session, outside the Node
mutation lock and production SQL writers, with one original role request live.
The appended shard RPC checks historical guild membership, exact layout/owner/
checkpoint hash, root-authenticated coding entry and paired local READY custody.
It verifies full bytes and rechecks custody after reading. Current heads or
post-Forget placement projections supply no substitute authority. The client
checks original role identity/commitment and bounded canonical peer-owner maps;
failed roles yield to original alternatives. Complete source and blob checks
and the original final retained private writer still govern publication.
Two real QUIC cases cover both layouts, missing live sources, Retire/Forget,
unauthorized/wrong-context callers, restore with the Node mutex held, cancellation
during peer reads, interrupted rename and source-free replay after network
shutdown. A third case covers writable journal use and exclusion after Node drop.
Seed/private bootstrap discovery/reconstruction, full operation/global/physical
admission, normal producer/distributed activation and remaining M6 gates stay
open. Dense 1 TiB and native Windows/macOS hardware tests remain user-deferred.
Frozen qualification passes 1,557 distinct cases: 639 fresh and 918 exact
unchanged reused. All 576 ordinary Node and 23 process acceptance cases
pass, along with four provisioned Linux native cases. Unchanged Store,
Git, Core and three bulk gate executables match their qualified parent
exactly. Format, strict locked all-target workspace Clippy, builds, frozen
source/binary checks and native cleanup pass. There are 121 unexecuted
ignored cases. Independent audit verifies 379 inputs and 23 executables.
Exact superseded-binary retirement reclaims 8.28 GiB; target uses
52.51 GiB. Current binaries, failed/older qualified evidence, 14 auxiliary
WIP files and all 10 installed roots remain preserved. Evidence:
`/tmp/mb-m6-retained-peer-restore-iipr46fk`.

Private bootstrap recovery from retained public evidence (2026-10-14):
The exact retained restore path can reconstruct a missing private catalog from
its original signed bootstrap and encrypted page sources. A per-revision source
locator index replays each original public source frame; hints supply no source
or byte authority. Bootstrap authentication precedes trusting private roots. New private staging requires an explicitly configured page quota.
Original retained coding witnesses and local READY or authenticated peer roles
recover each source, with complete original Merkle and byte-root checks before
private page decryption. Child-first staging and complete stream/graph validation
precede the existing atomic private publication writer. Pending bootstrap/page
work is charged before fetch and staging; publication transfers custody to the
original checkpoint owner. Completed journals remain charged until retirement.
Cancellation retires one owned row/page per transaction and preserves shared
published revisions. Both layouts exercise a fresh directory containing only
public metadata, corrupt peer bytes, cancellation during bootstrap fetch, ABORT
and IGNORE publication faults, retry, reopen and retained-owner retirement.
Frozen qualification passes 1,561 distinct cases: 1,498 fresh and 63 reused
from exactly unchanged executables. All 578 ordinary Node, 513 Store, 131 Git,
210 Core and 23 process acceptance cases pass, together with three bulk gates
and four provisioned Linux native cases. Format, strict locked all-target
workspace Clippy, builds, frozen source/binary checks and native cleanup pass.
Independent audit verifies 383 inputs and 23 executables; 121 ignored cases
remain unexecuted. Verified retirement removes 23 superseded archive paths and
21 exploratory executables, reclaiming 17.39 GiB. Incremental cache cleanup
reclaims another 6.32 GiB, for 23.72 GiB total. Target uses 58.88 GiB. Current
binaries, failed/older qualified evidence, 14 auxiliary WIP files and all 10
installed roots remain preserved. Seed/network public-root discovery, complete
operation/global/physical admission, normal producer/distributed activation,
legacy recovery and remaining M6 gates stay open. Dense 1 TiB and native
Windows/macOS hardware tests remain user-deferred.
Evidence: `/tmp/mb-m6-private-bootstrap-recovery-scskxz8e`.

Bind represented catalog capacity to database backing (2026-10-14):
An optional durable CatalogResourcePolicy binds the existing immutable
CatalogCapacityPolicy to active all-table record, main-page, journal and
immutable-page ledgers. Installation uses one writer, exact bounded policy/guard
rows and an independent enrollment marker. Missing, enlarged, reduced or
substituted backing fails closed at existing capacity admission/publication
checks. Public quota resize APIs reject conflicting limits in their own writer;
parity stores retain their separate policies. A late private publication fault
rolls back the bootstrap, source indexes, completion marker and callback writes.

The derivation charges page occurrences and persistent source/chunk/custody
indexes separately; coding transcript fragments remain page BLOB contents rather
than fabricated individual SQL rows. It includes duplicated locator/key credits
and original represented metadata, with explicitly configured database/journal
headroom. For the supported one-owner dense 1 TiB declaration it derives
5,010,809,639 rows, 14,899,935,718,308 accounted bytes, 3,637,679,875 pages and
14,987,241,085,032 journal bytes. These conservative local credits fit SQLite's
supported page range; they are not measured allocation or dense recovery proof.
Four Store regressions and the extended normal Node configuration/startup/reopen
case pass. Frozen qualification passes 1,565 distinct cases: 1,292 fresh and 273
reused from exactly unchanged executables. All 578 ordinary Node, 517 Store,
131 Git and 23 process acceptance cases pass, plus three bulk gates and four
provisioned Linux native cases. The unchanged Core executable preserves its 210
qualified cases. Format, strict locked all-target workspace Clippy, builds,
frozen source/binary checks and native cleanup pass. Independent audit verifies
384 inputs and 23 executables; 121 ignored cases remain unexecuted. Verified
retirement removes 23 superseded archive paths and two exploratory executables,
reclaiming 10.23 GiB. Target uses 58.88 GiB. Current binaries, failed/older
qualified evidence, 14 auxiliary WIP files and all 10 installed roots remain
preserved. Scratch/volume/filesystem reservation, concurrent operation admission,
policy adoption, normal paged production/distributed activation, seed
orchestration and remaining M6 gates stay open. Dense 1 TiB and Windows/macOS
hardware remains user-deferred.
Evidence: `/tmp/mb-m6-resource-policy-tm8b69kx`.

Durable public checkpoint acquisition and full peer recovery (2026-10-14):
Public acquisition now persists the exact original certificate, independent
history trust hash, bounded work ledger and deterministic per-root staging
owners. Paired job rows and exact readback reject partial or silently ignored
writes. Reservations precede page fetches; actual owned pages remain bounded
by each authenticated root. Acquisition traverses every authority, source,
packing and coding tree child-first and resumes committed prefixes. Peer I/O
uses the independent leased restore session outside Node and SQL writer locks.
The client fetches and verifies the original certificate over authenticated
QUIC. Downloaded pages grant staging ownership; promotion revalidates complete
original history, packing/coding joins and predecessor transition before the
ordinary retained public owner and durable restore indexes are published.
Cancellation fences late arrivals and retires one pin/root per transaction,
preserving independently published shared custody and restart fences.
Both layouts pass focused cases that remove the entire original Node directory,
fetch public metadata from a surviving different holder, resume an interrupted
fetch, cancel during a peer read, reconstruct missing private metadata, restore
exact native/Git bytes and reopen the receiving Node. Store cases cover ABORT
and IGNORE insertion/update/deletion faults, damaged paired state, quota rollback
and rejection of extra shared-page pins beyond the original root's allowance.
Frozen qualification passes 1,569 distinct cases: 1,296 fresh and 273 reused
from exactly unchanged executables. All 580 ordinary Node, 519 Store, 131 Git
and 23 process acceptance cases pass, plus three bulk gates and four provisioned
Linux native cases. The unchanged Core executable preserves its 210 qualified
cases. Format, strict locked all-target workspace Clippy, builds, source/binary
hash checks and native cleanup pass. Independent audit verifies 388 inputs and
23 executables; 121 ignored cases remain unexecuted. Verified retirement removes
23 superseded archive paths and two exploratory executables, reclaiming 10.24 GiB.
Target uses 58.91 GiB. Current binaries, failed/older qualified evidence, 14 auxiliary
WIP files and all 10 installed roots remain preserved.
Automatic DHT discovery/history bootstrap,
normal paged production/distributed activation, complete scratch/volume/global
admission, legacy completion and remaining M6 gates remain open. Dense 1 TiB
and Windows/macOS hardware qualification remains user-deferred.
Evidence: `/tmp/mb-m6-public-acquisition-q_0ftu3y`.

Bounded original-history peer bootstrap before retained recovery (2026-10-14):
An explicit peer recovery operation fetches original genesis, bounded event tails
and one original coding transcript/binding at a time. The recovered seed's original
genesis signature/key and the existing durable original-history validator govern
adoption and every event's complete effects. A selected tip remains a hint; only
replayed original quorum events establish authority. A conservative complete work
declaration is checked before fetches and stored in an immutable paired journal.
Original event/evidence records, compact authority, history point indexes and the
journal's progress share the existing publication writer and final readbacks.
No growing flat history is collected, and no SQL writer or Node lock spans peer
I/O. Verified prefixes resume after reopen; cancellation fences late responses and
identity reuse while retaining authentic shared history. Completion requires the
exact selected tip. Capacity backing is rechecked under the publication writer.
The optional capacity-policy getter now composes inside an enclosing writer,
preserving backing checks and the caller's rollback. Two local history cases cover
ABORT/IGNORE publication faults, wrong tips, corrupt signatures/state, immutable
target/budget, prefix reopen and cancellation. A Store regression checks configured
and unconfigured reads plus damaged backing under a writer. Both real QUIC layouts
start the receiving Node from its seed alone, retrieve original history and coding
evidence from a surviving holder, then acquire public catalogs and complete exact
native/Git restore after the entire original Node directory is removed.
Frozen qualification passes 1,572 distinct cases: 1,299 fresh and 273 reused
from exactly unchanged executables. All 582 ordinary Node, 520 Store, 131 Git
and 23 process acceptance cases pass, plus three bulk gates and four provisioned
Linux native cases. The unchanged Core executable preserves its 210 qualified
cases. Format, strict locked all-target workspace Clippy, builds, source/binary
hash checks and native cleanup pass. Independent audit verifies 390 inputs and
23 executables; 121 ignored cases remain unexecuted. Verified retirement removes
23 superseded archive paths and two exploratory executables, reclaiming 10.27 GiB.
Target uses 60.02 GiB, including the new preserved nested-read failure binary,
source snapshot and log. Current binaries, failed/older qualified evidence,
14 auxiliary WIP files and all 10 installed roots remain preserved.
Automatic DHT selection/publication,
predecessor checkpoint chain recovery, normal paged production/distributed
activation, full global/physical admission, legacy completion and remaining M6
gates stay open. The work declaration is not a physical reservation or dense
qualification. Dense 1 TiB and Windows/macOS hardware runs remain user-deferred.
Evidence: `/tmp/mb-m6-history-bootstrap-ncgbzx4c`.

Historical predecessor proofs and separate checkpoint recovery progress (2026-10-14):
The durable original-history view derives bounded membership at an exact original
event tip. It reads fixed tip/epoch rows, verifies the original event certificate,
rechecks canonical bytes and fences the complete current index. Checkpoint recovery
replays the selected original prefix for writer, coding and transition validation,
even after later quorum changes or writer revocation. A completed predecessor proof
must carry the certified original-history transition marker; generic quorum-bound
transition proofs do not satisfy this recovery boundary.
An independent paired recovery tip advances only with a completed acquisition and
published original public metadata owner. Its exact certificate, trust hash, budget,
layout and generation are checked. Failed or ignored tip writes roll back acquisition
completion. The active recovery tip fences owner/job cancellation; explicit tip
cancellation preserves public owners and original protection heads while fencing late
completion. Normal protection heads and activation remain separate. Peer acquisition
can carry one complete predecessor proof between steps, using the existing authenticated
certificate/page RPCs and leased restore session. Historical READY custody retains
full original witness and byte checks.
Both layout chain cases pass focused tests for second-generation proof validation,
ABORT/IGNORE tip publication faults, interrupted child acquisition and receiver reopen,
missing/uncertified predecessors, later writer rotation/revocation, and exact native/Git
restore from original retained parity. The historical lookup case verifies every original
tip across later membership/quorum changes, reopen, insufficient work and corrupt signatures.
Both real QUIC seed-only cases also fetch an older checkpoint after a later quorum event.
Frozen qualification passes 1,575 distinct cases: 1,302 fresh and 273 reused
from exactly unchanged executables. All 584 ordinary Node, 521 Store, 131 Git
and 23 process acceptance cases pass, plus three bulk gates and four provisioned
Linux native cases. The unchanged Core executable preserves its 210 qualified
cases. Format, strict locked all-target workspace Clippy, builds, source/binary
hash checks and native cleanup pass. Independent audit verifies 393 inputs and
23 executables; 121 ignored cases remain unexecuted. Verified retirement removes
23 superseded archive paths and two exploratory executables, reclaiming 10.28 GiB.
Target uses 62.29 GiB, including two new preserved fixture failure binaries with
source snapshots and logs. Current binaries, failed/older qualified evidence,
14 auxiliary WIP files and all 10 installed roots remain preserved.
Automatic DHT discovery/selection, legacy
predecessor recovery, complete ancestry retention/retirement, normal paged production
and distributed activation, full global/physical admission and remaining M6 gates stay
open. Dense 1 TiB and Windows/macOS hardware runs remain user-deferred.
Evidence: `/tmp/mb-m6-checkpoint-chain-fzqs3acu`.

Independent public predecessor custody (2026-10-14):
Recovery successors now archive their exact predecessor's original certificate,
full-proof receipt and all public metadata roots before moving the paired recovery
tip. The independent owner copies one root per short writer, authenticates EOF
against frozen source counters and resumes after reopen. It carries no private,
native, bootstrap or READY payload ownership. Paired progress/link records and
readbacks reject failed or ignored writes; active recovery progress fences archive
cancellation. Explicit adoption verifies the exact original parent before adding
ancestry to an older recovery tip. Existing peer certificate/page reads also serve
the exact public archive after source retirement, checking guild, layout, hash
and each authenticated root/path. Original retention, acquisition and wire
layouts are unchanged.
Two archive lifecycle cases pass ABORT/IGNORE progress and pin faults, interruption,
reopen, source-owner retirement, authenticated public reads, private-read rejection,
archive cancellation and permanent ID fencing. Both layout chain cases also pass
paired-link faults, explicit ancestry adoption, predecessor staging/public retirement,
archived certificate/page reads, receiver reopen and exact native/Git restore.
Frozen qualification passes 1,577 distinct cases: 1,304 fresh and 273 reused from
exactly unchanged executables. All 584 ordinary Node, 523 Store, 131 Git and 23
process acceptance cases pass, plus three bulk gates and four provisioned Linux
native cases. The unchanged Core executable retains its 210 qualified cases.
Format, strict locked all-target workspace Clippy, builds, source/binary hashes and
native cleanup pass. Independent audit verifies 394 inputs and 23 executables;
121 ignored cases remain unexecuted. Verified retirement removes 23 superseded
archive paths and two exploratory executables, reclaiming 10.30 GiB. Target uses
63.42 GiB. All 13 failed artifacts, 29 older archive paths, 14 auxiliary WIP files
and 10 installed roots remain preserved.
Automatic proof reconstruction from archived chains, precise per-descendant archive
retirement, automatic DHT selection, production/activation and complete resource
admission remain open. Dense 1 TiB and native Windows/macOS runs remain user-deferred.
Evidence: `/tmp/mb-m6-ancestry-custody-4a8ngxmh`.

Reconstruct selected paged recovery authority after restart (2026-10-14):
A bounded recovery operation walks exact archived predecessor links into an encrypted
disposable SQL stack, then rebuilds original history, packing, coding and complete
transitions in generation order. Only the previous/current complete proofs remain
live. The selected recovery tip, exact custody descriptor and independently derived
historical trust fence every validation step. Reconstruction publishes no acquisition,
lookup, protection head or replacement certificate. Retired predecessor jobs remain
cancelled. Whole-chain validation declarations and bounded custody reads share an
explicit checked budget; each debit precedes its work. This work accounting does not
replace global quotas, physical admission or dense qualification.
Both layout cases pass three-generation recovery after staging/public/payload owner
retirement on the source and staging/public retirement on the receiver. Reopen
rebuilds the selected original proof from independently owned ancestors, preserves
cancelled jobs and recovery/protection heads, and completes exact native/Git restore.
Insufficient work, a missing intermediate link and cancellation after the first
rebuilt proof fail closed. Store cases check exact source descriptors, changed trust,
source retirement and reads inside an enclosing writer.
Frozen qualification passes 1,577 distinct cases: 1,304 fresh and 273 reused from
exactly unchanged executables. All 584 ordinary Node, 523 Store, 131 Git and 23
process acceptance cases pass, plus three bulk gates and four provisioned Linux
native cases. The unchanged Core executable retains its 210 qualified cases.
Format, strict locked all-target workspace Clippy, builds, source/binary hashes and
native cleanup pass. Independent audit verifies 396 inputs and 23 executables;
121 ignored cases remain unexecuted. Verified retirement removes 23 superseded
archive paths and two exploratory executables, reclaiming 10.31 GiB. Target uses
63.41 GiB. All 13 failed artifacts, 29 older archive paths, 14 auxiliary WIP files
and 10 installed roots remain preserved.
Precise descendant archive retirement,
automatic DHT chain selection, legacy predecessors, normal paged production and
distributed activation, complete resource admission and other M6 gates remain open.
Dense 1 TiB and native Windows/macOS runs remain user-deferred.
Evidence: `/tmp/mb-m6-proof-rebuild-t7h2jw1e`.

Shared traversal admission for durable public acquisitions (2026-10-14):
A resource-backed acquisition reserves its complete declared traversal budget from
one database-wide ledger before public-tree fetching/staging. Budget dimensions
remain independent; concurrent connections share credits and at most 64 jobs (or
the resource policy's smaller slot count). Paired immutable leases, held indexes,
counters and readiness markers survive reopen. Completion/cancellation release
credits in their publication writer; failed or ignored writes roll back both job
state and credit release. Cancelled IDs remain fenced by original job records.
Resource enrollment freezes new acquisition admission while a bounded cursor adopts one old
job per transaction. Unadoptable old debt remains explicit and cancellable; no old
job, original certificate, retained data or signed head is rewritten for admission.
A persistent insert trigger rejects unfunded older writers; exact schema/marker
validation rejects missing or altered enforcement on reopen. Node checks custody
before each public fetch/validation guard and exposes adoption progress/steps.
This governs active acquisition traversal. Completed-proof replay, other producers,
SQL/WAL/page/payload/scratch/physical reservations and full shared R2/R3 admission
still require their complete integration. Normal paged producers remain disabled.
Seven new Store cases pass independent work dimensions, existing/concurrent
connections, restart, one-job adoption steps, cancellation of excessive legacy
debt, job-slot limits, missing/altered enforcement and ABORT/IGNORE reserve/release
faults. Both public layouts release work only with complete owner publication;
failed completion keeps the job Building and its credits held. Existing resource
contract tests and both real QUIC acquisition/restore cases pass.
Frozen qualification passes 1,584 distinct cases: 1,311 fresh and 273 reused from
exactly unchanged executables. All 584 ordinary Node, 530 Store, 131 Git and 23
process acceptance cases pass, plus three bulk gates and four provisioned Linux
native cases. The unchanged Core executable retains its 210 qualified cases.
Format, strict locked all-target workspace Clippy, builds, source/binary hashes and
native cleanup pass. Independent audit verifies 398 inputs and 23 executables;
121 ignored cases remain unexecuted. Verified retirement removes 23 superseded
archive paths and two exploratory executables, reclaiming 10.31 GiB. Target uses
63.94 GiB, including both new preserved fixture failure binaries, source snapshots
and logs. All 15 failed artifacts, 29 older archive paths, 14 auxiliary WIP files
and 10 installed roots remain preserved. Dense 1 TiB and native Windows/macOS
qualification remain user-deferred. R1/R2/R3/R5/R7 and remaining M6 gates stay open.
Evidence: `/tmp/mb-m6-acquisition-work-l1vs9a84`.

Linux parity-volume writer admission (2026-10-15, focused qualification below):
Initial and established volume writers retain one directory through read-only
key/catalog admission, manifest publication, schema open and rekey. Database,
journal and manifest versions fence the first write. Preserved readers retain
capability paths through SQLite main/WAL opens after directory rename. Unknown
volumes with incomplete existing schemas reject without reinitialization;
manifest-only unregistered initialization can resume, while registered missing
databases stay failed. This does not close the complete R1 upgrade/recovery or
shared R2/R3 policy. Evidence: `/tmp/mb-m6-volume-owner-vid28npy`.

A real-daemon debugger probe confirms the pre-fix default caller could create
a new manifest and parity catalog in a replacement data pathname while its
original control directory and lock stayed held. The caller now supplies that
held directory and rechecks it before registry publication; default-volume
configuration/reactivation use the same binding. Directory ownership and write
permissions are checked at admission fences. The original failing executable,
source snapshot and probe remain under
`/tmp/mb-m6-default-volume-handoff-probe-pl_d55ra`; corrected-daemon and
volume-suite evidence is recorded below. Complete source and installed
qualification remain open.


Retained writer recovery and focused volume qualification (2026-10-15):
`f886221` authenticates original writer keys during public body admission and
leaves current-writer enforcement for new revisions to the complete certified
predecessor transition. Both layouts pass all three authority changes (rotation,
revocation and owner removal), hostile signed mutations, and restart after
predecessor retirement. The revised three-generation chain cases fail before
the fix and pass afterward, preserving original ancestry and exact native/Git
restore. All 81 ordinary volume cases pass, including eight writer-admission
cases; two provisioned volume cases remain ignored. The rebuilt real daemon
also passes the default-directory swap probe, with its identity checked against
the frozen binary manifest. Independent focused audits verify 401 source inputs
and the corresponding executed binaries. Evidence:
`/tmp/mb-m6-retained-writer-nfid0c74`.

The complete debug-source qualification did not pass: the fourth provisioned
native capture/packing lifecycle exceeded its unchanged 900-second limit.
Three bulk-memory gates and the preceding three native cases passed; the ordinary
workspace suites had not started. All source and binary hashes remained unchanged,
and mount/image/loop cleanup was verified. A diagnostic run of the exact failed
binary with phase breakpoints passes in 752 seconds under the same limit, including
packing, source-loss replay, restore and bounded retirement. It does not explain
the original timeout or qualify a replacement full run. The original failure,
24 executables and exact source snapshot are retained under
`/tmp/mb-m6-native-capture-timeout-_t11hqvs` and
`target/failed/f886221-native-capture-timeout`. The fixture now emits bounded
phase/progress diagnostics directly to the private log without changing its
payload, assertions, cleanup steps or timeout. Full qualification must rerun.
The queued installed build/recovery jobs stopped on the failed prerequisite;
no installed candidate was built. R1/R2/R3/R5/R7, normal paged integration and
remaining M6 gates stay open; deferred hardware acceptance is unchanged.

Full source qualification and first-coverage diagnostics (2026-10-15):
The complete C2 source gate on `c2c82ef` failed. All four provisioned native
cases passed, including the unchanged 900-second capture/packing fixture in
669.62 seconds; three bulk gates, Store (532), Git (131), process acceptance
(23), builds, format and strict Clippy passed or reused exact executable bytes.
The ordinary Node suite reported 593 passed, one failed and 29 ignored in
2,809.88 seconds. `offline_first_spare_renews_live_checkpoint_coverage` exceeded
its first 90-second uninterrupted coverage wait while all five nodes were still
online, before the offline-spare injection. This is distinct from its later
renewal wait and from the historical 5,400-second relay-only missing-signer stall.
The failed source snapshot and all 23 exact executables are preserved with
independently verified SHA/inode/mode identities; source and binaries stayed
unchanged, and owned mount/loop cleanup passed. Both installed queues stopped
at the failed prerequisite. No installed candidate was built or tested.

The first-wait failure branch now records worker completion flags and per-node
launch/activation/delegated progress through nonblocking mutex inspection, then
preserves the fixture directory for inspection. The original deadline, payload,
assertions and successful path are unchanged. Its frozen full-workspace build
has the same 554 runtime-library feature selections as the failed candidate.
The exact failing case passes in isolation (76.68 seconds), and a four-thread
cohort with the three long-running cases overlapping the original failure passes
all four cases (322.32 seconds). These are diagnostic positives; they identify
no cause and do not qualify the failed full source or close R5/R7. Formatting and
strict workspace/all-target Clippy pass. Independent audit verifies all 401 frozen
source inputs, the executed binary identity and both selected case inventories. Preserve both unexplained timeouts; qualify subsequent source
with these diagnostics without extending deadlines or weakening protection.
Evidence: `/tmp/mb-m6-native-phase-qual-wnub781m` and
`/tmp/mb-m6-coverage-diagnostic-u1wi9jdl`.

Explicit cumulative traversal pool policy (2026-10-15):
An optional immutable CatalogTraversalPoolPolicy expands shared traversal credits
only after the existing resource contract and acquisition adoption are active.
The policy independently bounds bytes, records and page occurrences and cannot
shrink the original pool. Each acquisition retains its original per-checkpoint
limit; original resource-policy, job and lease encodings are unchanged. Paired
bounded records, a version marker and transactional readback preserve all old
job bytes and debt during enrollment/replay. Installation fails atomically on
aborted or ignored writes; missing/altered pairs or markers reject reopen.
All ten focused acquisition-work Store cases pass, including three new cases
covering concurrent independent dimensions, single-job limits, immutability,
reopen and enrollment faults. Strict Store all-target Clippy and formatting pass.
This is a work-credit policy,
not physical backing or completed-proof permit integration. Other producers,
SQL/WAL/payload/scratch reservations and full shared R2/R3 admission remain open;
normal paged producers remain disabled.

Kernel-owned complete-proof traversal admission (focused qualification, 2026-10-16):
Complete recovery-proof reconstruction reserves whole-chain work from the same
cumulative ledger and bounded slots as durable acquisitions before scratch or
ancestry traversal. Guards recheck paired leases; setup prepays admission,
release and failed-finish cleanup. Short verified writers release work only
after traversal stops. Failed cleanup leaves debt. The scope grants no recovery,
certificate, history, payload or publication authority.

Review reproduced premature reclamation through independent module/PID contexts
and an actual OverlayFS alias of a live catalog. Kernel OFD locks on a separate
empty file replace PID/weak-token guesses. Paired domains bind the actual catalog
and lock inode; creation is synced and held directory/file mappings are checked.
No extra descriptor opens the SQLite main file. Btrfs, ext4, XFS and tmpfs are
supported; layered/remote filesystems and foreign-device main-file mounts reject
before inferring independent copies. OverlayFS is explicitly unsupported.

New domain envelopes are version 2. Original version-1 domains remain readable;
the original catalog can reclaim a stopped kernel slot. Copies retain version-1
debt, and a new UUID/version is installed only without current scopes. Experimental
process-owner v1 envelopes retain their exact bytes and remain debt even in a
copy: their filesystem provenance cannot prove independence. Proven version-2
copies drain inherited scopes before rebinding, preserving original live credits.
Reclamation releases at most one abandoned scope, never a resumable acquisition.
Signed/wire, original acquisition job/lease and resource-policy formats stay intact.

The frozen candidate passes 24 Store cases (19 work, three lock, one provisioned
PID-namespace and one provisioned OverlayFS) plus both three-generation resource-
backed Node layouts. Coverage includes write faults, failed Drop, actual SIGKILL,
damaged pairs, directory/file replacement, original/copy legacy debt, version
upgrade, mixed budgets, live ownership and exact native/Git recovery after
retirement, writer changes and reopen. Strict workspace/all-target Clippy,
formatting, diff and source/executed-binary identity checks pass. The OverlayFS
mount is verified unmounted; its small fixture is retained for inspection.
Evidence: `/tmp/mb-m6-kernel-local-fs-1xcjw5mf`. Original red evidence remains preserved at
`/tmp/mb-m6-live-owner-red-16g84bt1` and
`/tmp/mb-m6-live-overlay-red-s_dep78t`, including source and executable identities.

This closes the focused owner-domain and recovery work-scope slice. Physical
SQL/WAL/page/payload/scratch backing, other producers, distributed current
activation and normal paged integration remain open. Normal producers stay
disabled. R1/R2/R3/R5/R7 and M6 remain open; dense 1 TiB and native Windows/macOS
qualification remain user-deferred. A complete current-source qualification is
still required with the initial-coverage diagnostics before installed jobs.

Complete current debug-source qualification (2026-10-16):
`d8e0581` passes 1,613 distinct fresh cases across all 19 ordinary
workspace drivers, three bulk-memory gates, both provisioned kernel ownership
probes (PID namespaces and OverlayFS), and four native capture/recovery cases.
The ordinary suites pass Core 210, Store 547, Git 131, Node 594 and process
acceptance 23; all other ordinary targets pass. No executable-result reuse was
needed. Format, strict locked workspace/all-target Clippy, four program builds
and the real default-volume directory-swap probe pass. Independent audit verifies
all 407 frozen source inputs and 23 executed programs/drivers, original failure
artifacts, auxiliary WIP and installed roots. Native mount/image/loop cleanup
is verified. 121 ignored cases remain unexecuted; this is the recorded Linux
source slice, not the complete R7 native/upgrade/multi-volume/Tor/platform matrix.

The previously failing initial coverage case passes inside this complete Node
run with its original 90-second deadline, payload and protection assertions.
The long native capture/packing lifecycle passes in 644.67 seconds under its
original 900-second limit. A low-cost read-only sampler records CPU/thread
scheduling, memory and I/O for the latter part of the run. These positives do
not explain the earlier initial-coverage failure, native timeout or historical
5,400-second relay-only stall; preserve their separate source/binary/log evidence.
R5 causal diagnosis remains open. No installed candidate was built or tested.

Evidence: `/tmp/mb-m6-shared-traversal-qual-s1de_h23`; independent `final-audit.json`, full per-case inventories,
source and binary manifests, native phase logs and `runtime-resources.jsonl`.
The isolated scratch-pool/work-accounting branch remains unqualified and is not
part of this source set. R1/R2/R3/R5/R7, shared physical admission, distributed
activation and normal paged production/retention/recovery remain open. Dense
1 TiB and native Windows/macOS qualification remain user-deferred.

Standalone durable capture/recovery consumers (focused qualification, 2026-10-16):
Original runtime on `553dbed` passes the regression's original metadata/byte
admission, then treats unfinished relocation as unavailable old data and
attempts a fresh reflink capture. Corrected source `54801e4` resolves standalone
dense/sparse capture and recovered-anchor reads through the durable catalog
cursor. A second rename returns to that resolver. Pending old-anchor reuse
requests retry while retaining original ownership. Recovery checks signed
metadata and bytes before completing assistance; final records retain the
actual discovered path instead of restoring the stale immutable hint.

The valid fixture retries across fresh processes in a 5,000-entry namespace,
requiring unchanged original manifests/recipes while pending, exact-byte
completion and journal cleanup. Independent audit verifies identical fixture
code in the negative and positive drivers. Initial selector-only and wrong
File-versus-FileV2 fixture failures prove no production cause and remain
separately preserved. The valid fixture carries actual native identity/extents
and explicitly passes original metadata validation in parent and fresh child.

All 36 ordinary snapshot cases and all eight provisioned Btrfs snapshot cases
pass, covering capture repair, old-intent migration, Git/source-loss recovery,
reanchoring after capture-before-commit interruption, durable retirement and
bounded directory handles: 44 distinct cases in 45 executions. Strict locked
workspace/all-target Clippy and formatting pass. Independent audit verifies all
407 frozen inputs, one executed driver and exact selected/passed inventories.
The owned Btrfs mount, loop and image are verified cleaned. Evidence:
`/tmp/mb-m6-valid-discovery-red-wsdkvy6n` and
`/tmp/mb-m6-valid-discovery-green-ju7em9d8`.

This closes the standalone read-consumer slice, not the enclosing integration.
Best-effort cleanup still has process-local paths; operational retry/backoff,
other consumers/filesystems/platforms, complete admission and normal paged
production/retention/recovery remain open with R1/R2/R3/R5/R7. This is not a new
complete-source or installed-artifact gate and explains none of the original
initial-coverage/native-capture/relay-only observations. Dense 1 TiB and native
Windows/macOS qualification remain user-deferred.

Funded scratch ownership binding (focused qualification, 2026-10-16):
The separate pool reserves full per-VFS physical ceilings and job slots before
anonymous scratch creation. Actual fallocate, checkpoint-copy reserves and
shared headroom remain mandatory. Retained-proof callers prepay bounded
pool/reclamation and volume-registry work before scratch indexes and stack.

Review withheld `309d0e1` despite its643 distinct passing cases. Exact regressions
on `4bf685d` show a lease accepting a recycled main-file inode and an empty-ledger
restore granting over a live reservation. The first O_PATH/unused-slot correction
still fails on `ecfc26e`: an old small declaration impersonates a later full-pool
owner of its reused slot. All three failed source/driver/log identities remain
preserved; the earlier positive remains separate evidence.

Corrected `ad2c2e9` pins the original main inode with O_PATH and binds each scope
to a separately locked UUID owner file plus exact device/inode. A private
directory per class holds at most one empty owner file per slot (64 total),
including crash orphans. Under the existing writer, bounded scans compare all
live owner files with current declarations and aggregate liveness; unknown or
reused owners refuse new grants. Dead debt stays charged. All unused aggregate
slots are also probed. The selected slot replaces only a stopped prior owner;
file/directory entries are synced before committing. Guards check both mappings
through final close. Reclamation still requires a free aggregate slot or proven
independent copy. Existing files are inspected through O_PATH before ordinary
I/O, avoiding a substituted SQLite main-file descriptor.

Domain3, scratch declaration2 and traversal declaration3 append local ownership.
Explicit codecs preserve original bytes/hashes; old kernel debt blocks new
grants until stopped and drained. Version1 copies and old process envelopes
keep unproven debt; proven2/3 copies retain independent reclamation. Original
resource-policy, signed/wire and per-checkpoint admission formats stay intact.

All18 scratch cases pass, including all three reproduced failures, partial
restores, owner replacement, bounded churn, original legacy replay and independent
DELETE-mode writer exclusion after pin close. All5 lock,20 work,7 scratch/VFS
and both actual namespace/OverlayFS probes pass. Node retained recovery2,
volume81 and ordinary snapshot36 pass; Btrfs funded scratch and all8 native
snapshot cases pass: 179 distinct cases in181 executions. Strict locked
workspace/all-target Clippy and format pass. Independent audit verifies410
inputs, both executed drivers, exact case inventories, unchanged qualified
standalone source code and preserved negative artifacts. Owned OverlayFS and
Btrfs mounts, loop and image are verified cleaned. Evidence:
`/tmp/mb-m6-owned-scope-qual-n2wz8784`; original negatives at
`/tmp/mb-m6-scratch-owner-red-0zn7e2qb` and
`/tmp/mb-m6-scratch-reused-slot-red-lqv6lhm4`.

This qualifies new funded ownership within preserved local bookkeeping. Complete
old-writer/quiescent enrollment, database relocation/restore policy, all-producer/
global physical admission, persistent SQL/WAL/volume backing, distributed
activation and normal paged production/retention/recovery remain open. No
producer is enabled. This is focused integration, not a complete current-source
or installed-artifact gate, and diagnoses none of the three historical R5
observations. R1/R2/R3/R5/R7 and M6 remain open; dense1TiB and native Windows/macOS
qualification remain user-deferred.

### 2026-10-16 — Initial funded scratch ownership enrollment

Two preserved regressions on `711d450` restore the valid pre-first-lease
snapshot, then move or hard-link the same main inode into another directory.
Both admit 9 bytes against a 9-byte pool while an original 3-byte lease is live.
Qualified `5ac6b59` commits the synced paired lock domain with initial scratch
enrollment. Local ledger/marker version 2 requires the domain even when empty;
version-1 bytes remain readable, but unanchored old pools cannot grant or
automatically upgrade. Funded ownership refuses hard-linked main files, while
whole-directory relocation with bookkeeping preserves live capacity.

All 574 ordinary Store cases, actual namespace/OverlayFS probes and focused
Node recovery/volume/snapshot/native integration pass: 703 distinct cases in
707 executions. Enrollment write faults, missing domain pairs, both identical
regression test sources, legacy inspection and whole-directory relocation are
covered. Strict locked workspace/all-target Clippy, formatting and independent
410-input/two-driver/exact-case audit pass; original negatives and owned native
mount/loop/image cleanup are verified. Evidence:
`/tmp/mb-m6-enrollment-domain-qual-e1obth6s` and
`/tmp/mb-m6-enrollment-domain-red-6i988wob`.

This closes the initial funded scratch-domain gap. Full old-writer/quiescent
upgrade, traversal enrollment/relocation, all-producer/global physical SQL/WAL/
volume backing and normal paged integration remain open. No producer is enabled.
The full `d8e0581` source gate is historical after subsequent source changes;
new combined complete-source and installed qualification remain required. R5's
initial-coverage, native-capture and historical relay-only observations remain
separate and unexplained. R1/R2/R3/R5/R7 and M6 remain open; dense 1 TiB and
native Windows/macOS qualification remain user-deferred.

### 2026-10-16 — Preserve retained recovery anchors on retry errors

Actual native `090ee7e` partially transfers retained ownership, verifies the
replacement is readable/pinned, then retries after a temporary payload EACCES.
The destructor deletes that still-owned replacement; the intended assertion
fails after admission preflights. Qualified `956a238` removes that destructor
and leaves ownership with the already durable capture/recovery intent. Checked
plan discard, abandonment and retirement retain their original pin guards.

The regression now preserves exact binding/generation and readable bytes, then
finishes fresh recovery/retirement. All 36 ordinary snapshots and eleven native
snapshot/retained cases pass: 47 distinct cases in 48 executions. Strict locked
workspace/all-target Clippy, formatting and independent 410-input/one-driver/
exact-case/fresh-compiler audit pass. Native cleanup and original failure
source/driver/image preservation verify. The fixture's sole lexical adjustment
is decimal zero to octal `0o000`, with identical permission bits. Evidence:
`/tmp/mb-m6-pinned-retry-red-rebuilt-zzocozlf` and
`/tmp/mb-m6-intent-owned-recovery-qual-octal-6qg68qcl`.

The initial copied cached driver ran zero cases and was rejected by inventory;
explicit rebuild produced the real negative. The first positive attempt stopped
at the fixture literal lint before tests. These are separate control records.
Other cleanup/replay consumers, operational backoff, complete R1/R2/R3 admission
and normal paged integration remain open; producers stay disabled. Full current
source/installed, R5 causal and remaining M6 gates remain open. Dense 1 TiB and
native Windows/macOS qualification remain user-deferred.

### 2026-10-16 — Preserve completed root payloads on malformed replay

Actual native `4a60cf4`, with the prior destructor fix, transfers retained
ownership and verifies its pinned source remains readable after local manifest
damage and restored plaintext loss. Backend replay deletes the completed
candidate before recapture fails, invalidating that still-owned source. Qualified
`6586467` instead returns the completed-manifest error before cleanup. Valid
completed replay and initial capture retain their existing behavior; checked
discard/abandonment retains deletion responsibility.

The identical complete regression test source preserves binding/generation,
pins and readable bytes, then completes fresh recovery/retirement after local
manifest repair. All 27 ordinary anchors, withdrawal1, ordinary snapshot36 and
native anchor18/snapshot8/retained4 pass: 94 distinct cases in 95 executions.
Strict locked workspace/all-target Clippy, formatting and independent 410-input/
two-driver/fresh-compiler/exact-case audit pass; native cleanup and original
failure preservation verify. Evidence:
`/tmp/mb-m6-owned-capture-replay-red-l1ykilkv` and
`/tmp/mb-m6-owned-capture-replay-qual-iyp5qixj`.

External-remount2, file/blob replay variants, final area-sync failure cleanup
and remaining consumer/backoff work remain open. This does not close complete
R1/R2/R3 admission, normal paged production/retention/recovery, R5 causes or
R7 current-source/installed gates. M6 remains open; dense 1 TiB and native
Windows/macOS qualification remain user-deferred.

### 2026-10-16 — Bind initial native traversal ownership

Actual regression `e3dbcdb` restores valid pre-scope work rows through SQLite,
then moves the same main inode while its original kernel owner remains live.
The relocated catalog grants the full pool. Corrected `86ed876` provides explicit
initial native resource enrollment, committing its synced paired domain and
local ledger/marker version 2 in the same writer. That version requires the
domain even before the first scope. Generic logical configuration and original
resource/signed encodings remain unchanged. Older anchored work stays supported;
unanchored catalogs remain inspectable and support durable logical jobs, but
cannot grant live traversal work or automatically establish quiescence.

Qualification passes all 579 ordinary Store cases, namespace/OverlayFS probes,
Node retained recovery2/volume81/snapshot36, and provisioned Btrfs traversal25/
funded-scratch1/snapshot8/retained4: 712 distinct cases in 740 executions. Strict
locked workspace/all-target Clippy, format and independent 410-input/two-driver/
exact-case/archive audit pass; native cleanup and original failure preservation
verify. Evidence: `/tmp/mb-m6-traversal-enrollment-red-xyq8st3b` and
`/tmp/mb-m6-traversal-enrollment-qual-rlkbx25j`. Full old-writer/quiescent upgrade,
complete restore/relocation policy, physical SQL/WAL/volume backing, normal paged
integration, R5 causes and current-source/installed R7 remain open. Producers
stay disabled; dense 1 TiB and native Windows/macOS remain user-deferred.

### 2026-10-16 — Borrow native SQL descriptors without changing locks

Qualified `6e90abf` adds a pinned C file-control extension that borrows the
existing Linux Unix-VFS descriptor. Native ownership now verifies the actual
main file's identity, link count and filesystem alongside the path/directory
checks. Rust uses no private native-file layout, global syscall hook, or extra
main descriptor whose close could release SQLite's POSIX locks. The original
SQLite/SQLCipher/OpenSSL versions and feature declarations are preserved; the
vendor archive and all original files have recorded checksums.

All 582 ordinary Store cases, namespace/OverlayFS probes, Node recovery2/
volume81/snapshot36, funded Btrfs scratch/traversal, eight native snapshots and
four retained recovery cases pass. The three new descriptor cases also repeat
on Btrfs: 715 distinct cases in 746 executions. Strict locked workspace/all-
target Clippy, format and independent 442-input/two-driver/source/archive/
upstream-provenance/native-cleanup audits pass. Evidence:
`/tmp/mb-m6-native-sql-file-qual-zssj11g9` and
`/tmp/mb-m6-native-sql-integration-jfhn_muh`. This is a descriptor/identity
prerequisite; physical SQL/WAL/SHM/temporary/volume reservation, complete
old-writer/quiescent policy, normal paged integration, full current-source/
installed qualification and R5 causes remain open. Producers stay disabled;
dense 1 TiB and native Windows/macOS qualification remain user-deferred.

### 2026-10-16 — Admit runtime native SQL file-family allocation

Qualified `1f3333d` adds an explicit Linux runtime physical VFS for new and
caller-owned existing control catalogs. Real private extents precede main,
WAL/rollback, SHM and anonymous temporary growth. Independent family/total/file
ceilings and free-space headroom bound admission; closed linked files and
unlinked live descriptions stay charged. Main identity is pinned before SQLite
opens it. Known shared/inline/encoded/unknown extents refuse admission, and a
nonempty Btrfs file must already have NoCow enabled. Generic logical APIs remain
available with their existing behavior.

Btrfs probes exposed inline short-header conversion despite NoCow and KEEP_SIZE
preallocation. Journal initialization now funds one full filesystem block;
native SHM reset funds its zeroed marker under the exclusive SQLite DMS lock.
Anonymous SQL temporaries transfer their existing descriptor into the native
adapter without reopening a procfs symlink. The native C extension remains
inside the pinned defining translation unit; no Rust private-layout access or
global syscall hook is introduced. All original vendor hashes/licenses and
dependency versions remain preserved.

Qualification passes 725 distinct cases in 764 executions: all 590 ordinary
Store, namespace/OverlayFS, Node recovery2/volume81/snapshot36, native descriptor/
traversal/scratch/snapshot/retained coverage and ten real Btrfs physical cases.
Those include full-transaction quota refusal/retry, actual filesystem ENOSPC/
retry, stopped-catalog reflink refusal before SQL initialization, four-mode
fresh-process crash recovery through the ordinary adapter, retained temporary
spill and directory relocation. Strict workspace/all-target Clippy, plain
SQLite C syntax, format, source/archive/two-driver/upstream/exact-case audits
and owned native cleanup pass. Failed attempts retain their exact source,
driver, logs and detached images. Evidence:
`/tmp/mb-m6-physical-sql-integration-s53h9st1` and
`/tmp/mb-m6-physical-io-btrfs-r2siostk`.

This qualifies per-connection runtime file admission. Persistent/global and
enclosing operation quotas, checkpoint/rebuild copy reserves, old-writer/
quiescent enrollment, parity volume coverage and normal paged integration remain
open. Partial creation/restart is still caller-owned. Producers stay disabled;
complete current-source/installed/R5/R7 gates and user-deferred dense 1 TiB and
native Windows/macOS qualification remain open.

### 2026-10-16 — Extend runtime physical admission to parity SQL catalogs

Qualified `efbe298` gives `ParityStore` the same explicit Linux runtime
physical creation/existing-open APIs and VFS ownership as control catalogs.
The shared private helpers preserve descriptor pinning and admit all native
SQL file-family growth before data I/O. Existing generic parity constructors
retain their behavior. Durable/global/enclosing volume policy and old-writer
adoption remain separate work; normal volume producers are not switched.

Four new cases pass on both the standard filesystem and Btrfs: fixed/variable
READY bytes and receipt/activation evidence survive reopen and ordinary reads;
a late physical allocation refusal rolls back the entire staged object and
retries; existing/wrong-volume/missing-main opens preserve data; and future
publication retains the original directory after rename. Fourteen combined
Btrfs control/parity cases also pass, including real ENOSPC and stopped shared
extent refusal. Focused qualification passes 177 distinct cases/executions on
this source, including 67 ordinary database, 12 directory, three descriptor and
81 Node volume cases. Strict workspace/all-target Clippy, format, fresh-driver/
source/archive/exact-case audits and native cleanup pass. Evidence:
`/tmp/mb-m6-parity-sql-integration-mcrfxq_2` and
`/tmp/mb-m6-physical-io-btrfs-h7oknki6`. This increment does not replace the
complete current-source/installed gate or close R1/R2/R3/R5/R7. Producers stay
disabled; user-deferred dense capacity and native platform gates remain open.

### 2026-10-16 — Authenticate a bounded local native policy with its key

Qualified `0d9d685` adds an explicit Core native key envelope format 2. Its
fixed 118-byte ciphertext authenticates the original 32-byte key and a 70-byte
policy containing a nonzero identity and native file-family/total/headroom/file
ceilings. A distinct wrapping context and exact lengths reject malformed,
altered, wrong-role/identity and unsupported records. The native decoder returns
the key with its validated policy; generic unwrap keeps its original v1-only
behavior. This makes missing future startup dispatch reject the new format.

All 214 ordinary Core cases pass, including four new compatibility, tampering,
semantic-boundary and full-width cases (218 executions with the focused repeat).
A synthetic original v1 envelope and its exact 62-byte canonical Postcard form
were generated through the previously qualified Core library before changes;
both remain readable and byte-identical. Strict workspace/all-target Clippy,
format and independent 447-input/fresh-driver/source/archive/original-library
fixture audits pass. Evidence: `/tmp/mb-m6-native-policy-core-qual-6em4yli1`.
No production path publishes or consumes format 2. Node startup/preserved-read
dispatch, fresh birth/restart, old-writer/restore policy, aggregate/enclosing
admission and normal producers remain open, together with R1/R2/R3/R5/R7 and
current-source/installed/deferred hardware gates.

### 2026-10-16 — Recheck the complete ordinary Node cohort after native SQL work

Frozen runtime baseline `efbe298` passes all 595 ordinary Node cases, including
`offline_first_spare_renews_live_checkpoint_coverage`, in 2,807.29 seconds. The
original four-thread cohort and 5,000-second overall runner bound are retained;
fixture payloads, individual deadlines and protection assertions are unchanged.
Thirty-one explicitly ignored Node cases remain outside this run. Independent
audit verifies the exact reused fresh driver, all 446 snapshot inputs/archive,
complete passing-case inventory and 559 process/thread/scheduling/pressure/I/O
samples. Evidence: `/tmp/mb-m6-physical-node-full-vglt6js3`.

This is ordinary Node evidence on the runtime baseline, before the subsequent
Core key-policy codec. It does not requalify the complete current workspace or
an installed artifact, diagnose any historical liveness observation or close
the required fault matrix. The original first-90-second coverage failure,
900-second native capture timeout and 5,400-second relay-only stall stay separate
and open. R5/R7 and the remaining R1/R2/R3/Milestone 6 gates remain open.

### 2026-10-16 — Inspect native-policy key envelopes without startup ownership

Qualified `e40dda0` adds explicit read-only decoding of authenticated native
key envelopes for control snapshots and preserved parity. It validates the
complete policy before opening SQL, then recovers bytes without granting native
file/work capacity. Linux mutable admission keeps original v1-only key decoding
and checks it before the newly permissive inspector, including existing catalogs.
Native-policy state therefore rejects before node lock creation or permission
changes until its dedicated birth/enrollment path exists.

Four new cases pass on the standard filesystem and Btrfs: closed, WAL-only and
live control/parity inputs remain preserved; fixed/variable data and receipt/
activation evidence stay exact; malformed/context/owner/length/version records
reject before callbacks; generic startup rejects both existing and missing
native-policy catalogs before ownership changes. All 85 volume, 16 source-policy
and 51 legacy inspection/export cases pass. Provisioned bind/renamed-root and
original manifest-only restart coverage also passes: 155 distinct cases in
159 executions. Strict workspace/all-target Clippy, format, independent
448-input/fresh-driver/source/archive/exact-case audits and owned native cleanup
pass. Evidence: `/tmp/mb-m6-native-policy-inspection-qual-lal21imp`.

This is read-only format support with retained mutable rejection. Native-policy
publication, fresh atomic birth/restart, copy/old-writer adoption, aggregate/
enclosing reservations and normal volume/paged production remain open. R1/R2/
R3/R5/R7 and complete current-source/installed/deferred hardware gates stay open.

### 2026-10-25 — Share native SQL physical admission across live connections

Implemented `a4eeed8` shares explicit native control/parity allocation pools by
pinned main inode within a process. Every connection accounts for the same
main, journal, SHM, anonymous temporary, total and file-slot allowance. Different
live limits or journal namespaces reject before SQLite opens. Native close
releases anonymous allocation only after its last binding closes; weak registry
entries grant no durable ownership. Reused bindings retain full private-extent
inspection. Existing key envelopes, generic constructors and mutable native-key
rejection remain unchanged.

Seven identical regression sources fail against the preceding native allocator/
VFS at `e23e4fa`, then pass after correction. They exercise independent temporary,
total and slot exhaustion, rollback/retry after native close, concurrent opens,
policy conflicts, aliases/journal namespaces and parity READY evidence/reopen.
All 601 ordinary Store and 21 physical cases on disposable Btrfs pass: 603
distinct cases, including actual filesystem exhaustion and stopped-sharing
refusal. Formatting, strict Store/all-target Clippy, an independent 394-input/
executable-identity audit and owned mount/loop/image cleanup pass. The separate
cross-process allocation-lock probe also passes with its original deadline.

The original negative binaries/sources/logs, first full-Store failure and
undersized 1 GiB native image remain preserved. The latter failed the existing
exhaustion fixture's greater-than-1-GiB assertion; fresh 4 GiB runs pass. The
first full Store run exposed two fixture interactions: its global lock probe
could be starved by other allocations, and the new temporary concurrency case
unnecessarily acquired the main writer lock. Final test-only probe isolation
and deferred temporary transactions retain the original deadlines and capacity
assertions. Evidence: `/tmp/mb-native-pool-regression-8yffoabm`, final `*-r2`
logs and `audit-r2.json`. The vendored bridge contract now also documents SHM
callback/DMS ordering and temporary-descriptor transfer ownership.

This is focused Store evidence. Durable policy/key birth/restart, cross-process
and old-writer/copy adoption, aggregate enclosing reservations, ordinary Node/
volume startup and normal paged integration remain open. Keep native-key mutable
rejection and disabled normal producers until those paths exist. R1/R2/R3/R5/R7,
complete workspace/installed qualification and deferred hardware gates remain
open; no historical liveness observation is diagnosed by these passes.

### 2026-10-25 — Durable native Store birth and process leases

Qualified code `9047752` adds explicit fresh control/parity creation/resume and
native reopen APIs. A private directory holds the exclusive kernel lease.
Three atomically published signed records bind the parent, lease/main inode,
database kind/identity and original format-2 key/policy. Birth/key publication
precedes SQL, main binding precedes initialization, and readiness follows the
paired SQL marker. Connections and reusable handles retain the original lease
and shared physical pool; immutable record mappings are checked before more
allocation. Retained linked journal tails count before SQL opens. Native journal
recovery remains under that lease and its original policy, and every returned
connection verifies its SQL binding. Generic writers and unmanaged rekey fail
closed; the SQL marker remains a format boundary on other platforms too.

Sixteen new Store cases cover seven partial/error and actual process-death
publication points, hot transactions in DELETE/TRUNCATE/PERSIST/WAL modes,
last-handle process exclusion, unchanged key/policy/data and fixed parity ACKs,
record/main replacement and damage, parent handoff, directory-copy refusal with
read-only recovery, temporary and retained-journal admission and concurrent
normal writes. An initial reusable-handle preflight mistook main/WAL data
changes for invalid ownership. Its exact failing source/binary/log are retained;
the unchanged regression passes with live-lease reuse and per-connection SQL
binding checks. A new Node case recovers from the birth without control.key,
while mutable startup rejects before key/lock/permission changes, including a
missing main. Original v1 envelope bytes and ordinary startup dispatch remain
supported; no ordinary native-policy writer is enabled by this increment.

All 617 ordinary Store cases, 86 volume, 16 source-policy and 51 legacy Node
cases pass. Disposable Btrfs passes 21 physical, 16 ownership and five inspection
cases, including actual ENOSPC and stopped-sharing refusal: 772 distinct cases
in 812 final executions. Formatting, strict workspace/all-target Clippy,
396-input/two-executable/source-archive audit and independent owned mount/loop/
image cleanup pass. Evidence: `/tmp/mb-native-owner-qual-cnl11s9t`, final
`*-current` logs, `current-btrfs` and `audit.json`.

This is an explicit Store foundation with same-host process-restart evidence.
Complete normal Node/volume creation/restart, managed rekey and old-writer/
restore/host-relocation adoption next. The fixed ownership bookkeeping also
needs enclosing funding alongside SQL/WAL/SHM/temporary, scratch, payload and
checkpoint/rebuild reservations. Normal paged production stays disabled. Full
workspace tests, installed artifacts, host reboot and deferred platform/capacity
qualification are not claimed. R1/R2/R3/R5/R7 and the remaining M6 gates stay
open; these passes diagnose none of the historical liveness observations.

### 2026-10-25 — Native Node birth and ordinary managed runtime

Code `859ce70` adds explicit Linux `Node::create_native` creation/resume with
caller-declared control/parity policies. An immutable signed profile persists
the original parent, volume UUID and both policies before SQL. Signed readiness
binds both original wrapped keys after the registry/profile transaction commits.
Ordinary Node opens validate this profile and inspect supported source state
read-only before lock/permission changes or SQL recovery. Control/parity readers
and configuration retain native owner handles and physical ceilings. Managed
configuration refuses implicit legacy volume creation; coding capacity hints
respect physical admission. Generic mutable native-key rejection remains outside
these authenticated paths. Existing default initialization still selects v1.

Read-only Store inspections carry pinned authenticated evidence without writer
claims or allocation credits. A distinct open description owns the kernel lease,
so retaining or dropping inspection handles cannot retain or unlock writers.
Admitted creation and reopen fence main/journal/private inputs through the
actual native main descriptor before SQL configuration. Six Node publication
points qualify both injected failure and actual process death, stable original
identity/key/policy, ordinary reopen, control configuration and fixed parity ACKs,
reader lifetime exclusion, wrong seed/policy, copy/legacy refusal, withdrawn
source rejection and control/parity handoff substitution.

Two discovered defects have preserved negative source/executable/log evidence.
An empty/absent creation handoff could publish more startup state after withdrawn
records appeared; the unchanged regression now checks no post-handoff mutation.
Btrfs NoCow initialization changed an empty partial main's ctime before descriptor
admission, causing a false conflict. Main initialization now follows the guard,
with writes/truncation blocked until it completes. The existing SQLite capacity
error contract for shared extents is preserved; its intermediate failure is also
archived. The same creation and physical regressions pass on the final source.

All 622 ordinary Store cases and 60 disposable Btrfs executions pass: 21 physical,
21 ownership, five preserved inspection, nine bootstrap, three runtime and one
parity handoff. The focused audit verifies 642 distinct cases in 682 executions,
399 code inputs, two exact executables/source archive, strict workspace/all-target
Clippy, format and owned mount/loop cleanup. Evidence:
`/tmp/mb-native-node-qual-rx_jdsbb`, final `*-r3` logs, `native-r3` and
`focused-audit.json`. The three detached negative images remain preserved.

The complete ordinary Node run subsequently finished on these exact binaries
with 612 passed, one failed and 32 ignored in 3,096.10 seconds. The first
90-second coverage wait of `offline_first_spare_renews_live_checkpoint_coverage`
failed before fault injection. Four threads and the documented 5,000-second
overall bound were retained. Its initial
intermediate default-concurrency attempt exhausted the 1,024-descriptor process
limit; that log, descriptor inventory, source and binary are preserved. The
current runner provides 65,536 descriptors and retains individual test deadlines.
The source gate remains failed; no complete ordinary Node/workspace or
installed-artifact pass is claimed. `node-negative-audit.json` verifies all
612 passing/one failing/32 ignored identities, 399 unchanged code inputs and
both exact executables/archive, 620 process samples (maximum 287 descriptors)
and a 35-file unchanged preserved fixture snapshot. This is separate from the
initial descriptor-exhaustion attempt and diagnoses none of the historical R5
timeouts. Investigation continues on the preserved initial-coverage failure.

Complete fresh CLI/default policy selection and additional native volume birth,
managed rekey, quiescent old-writer/restore/host-relocation adoption, host reboot
and enclosing ownership-bookkeeping/SQL/scratch/payload/checkpoint funding.
Normal paged producers stay disabled. R1/R2/R3/R5/R7 and the user-deferred native
platform/dense-capacity gates remain open.

### 2026-10-25 — Reproduce and trace initial coding coverage failure

The full ordinary Node prerequisite on `859ce70` fails the unchanged first
90-second wait of `offline_first_spare_renews_live_checkpoint_coverage` while
all five nodes are online. The original fixture `/tmp/.tmpnnElGg` has no remaining
open descriptors and a read-only 35-file forensic copy under
`/tmp/mb-native-node-qual-rx_jdsbb/r5-initial-coverage`; original/copy hashes and
the exact failed source/executable identities are verified. Read-only decoding
shows the healthy launch dispatched and the coordinator job Running, with no
verifier commitment. All five coding worker tasks remained live at timeout.

Diagnostic code `2303e79` adds opt-in bounded test traces of blocking-pool
scheduling, node-mutex acquisition/release and peer mutations, plus queued/
dispatched routing snapshots. No key or payload bytes are recorded. Production
behavior, fixture payloads, the 90-second deadline and protection assertions are
unchanged. Diagnostic compilation reuses the exact dependency artifacts selected
by the failed Node target's Cargo fingerprint; commands, source archives, runtime
feature/dependency hashes and diagnostic executables are retained. All-Node-test
Clippy passes using those dependencies.

An isolated traced run reproduces the first-wait failure with 19,295 events,
zero dropped events and 90.001716 seconds of coverage observation. No individual
mutex hold exceeds 0.85 seconds. The coordinator finishes its initial local work
at 4.787 seconds and then waits on its first verifier RPC; no verifier mutation
arrives. Unmodified isolated and subsequent traced positives remain diagnostic
comparisons, not fixes or complete qualification. Capturing the failed request's
routing/endpoint state is the next step; no cause is asserted yet. The distinct
900-second native capture timeout, 5,400-second relay-only stall, complete R5 fault
matrix and installed gates remain open.


### 2026-10-25 — Register delegated coding participant routes

`f543658` corrects a reproduced first-coverage routing omission. A delegated
coordinator can receive its plan over the delegator connection while having no
application route to the independent verifier. The negative trace captures a
queued challenge request with zero dial attempts, no connection and no retained
address; read-only decoding confirms that the coordinator's installed roster
already contains the verifier endpoint. Delegated execution now registers only
its assigned nonvirtual information owners, parity holders, delegator and
verifier from the current guild/epoch roster. Existing address admission retains
signed endpoint replacement/withdrawal authority, bounded caches and Tor policy.

The new regression exercises the real worker against an unpolled fresh routing
table and checks the route before its first RPC, so incidental discovery cannot
mask the omission. Identical test-module bytes fail on the prior implementation
at that assertion and pass with the fix, then complete the full original coverage,
offline-spare renewal and backup checks in 114.23 seconds. Both original coverage
fixtures pass together in 127.11 seconds; seven endpoint-authority, Tor and retry
cases pass too. The three initial coverage waits finish in 18.99/23.86/24.42
seconds under the unchanged 90-second deadline, with zero dropped trace events.
All-Node-test strict Clippy and formatting pass. The independent routing audit
verifies 400 code inputs, source archives, exact dependencies/executables and
identical before/after test modules. Evidence:
`/tmp/mb-native-node-qual-rx_jdsbb/r5-initial-coverage`, `routing-*` artifacts.

This is a demonstrated routing correction with 10 distinct focused passing cases.
Complete current-source qualification is still required before installed work;
the old full-source run remains a failed historical result. The original
900-second native capture and 5,400-second relay-only observations, the complete
R5 fault matrix and R1/R2/R3/R5/R7 remain open. Normal paged producers stay disabled.


### 2026-10-25 — Fence native Node readiness with the durable volume registry

An ignored registry insert on the actual native startup connection reproduced
signed readiness without the required volume registry. Startup returned an error,
but the signed file then prevented both normal open and explicit creation resume.
The 12-file failed fixture and exact source/executable/log are preserved under
`/tmp/mb-native-node-qual-rx_jdsbb/native-registry`. An earlier persistent-trigger
probe was correctly rejected by schema preflight and is not evidence for this
publication defect.

`27128c3` reads back exact canonical registry bytes inside the existing SQL
transaction, before the SQL profile and signed readiness. Ignored or changed
bytes abort that transaction. Identical before/after regression source proves
rejection before readiness, rollback of both registry/profile rows, successful
retry and ordinary reopen with original identities and policies. The isolated
implementation branch `2df623f` passes 19 ordinary and the same 19 disposable
Btrfs cases, with strict all-Node-test Clippy and formatting. Independent
`publication-audit.json` checks 400 inputs, exact source archives, dependencies
and executables, unchanged test source, the preserved negative and removal of
the owned image, mount and loop device.

The merged routing and registry fixes still require complete current-source
qualification before installed jobs. Existing R1/R2/R3/R5/R7, native CLI/default
policy selection, additional volume birth, managed rekey/adoption, enclosing
funding and deferred platform/capacity gates remain open. Paged producers remain
disabled.


### 2026-10-26 — Preserve the restored blocked-launch qualification failure

The complete ordinary run on frozen `26659ff` reports 1,703 passed, one failed
and 136 ignored across 19 test targets. Node has 614 passes/one failure/32 ignored
in 3,154.04 seconds; Core 214, Store 622, Git 131, process 23 and the other targets
pass. Formatting, strict workspace Clippy, Docker safety, packaging tests and all
target builds pass. `negative-audit.json` under
`/tmp/mb-m6-routing-registry-qual-32967msi` independently verifies all 454 tracked
inputs/archive, 23 executable identities, complete case inventories, four threads,
the original 5,000-second Node bound and 631 samples (287 maximum descriptors).
The source gate is failed; supplemental/installed queues did not start.

The sole failed case is the final 60-second restored-volume wait in
`blocked_launch_staging_yields_to_healthy_launch_after_reopen`. The previous
first-coverage fixtures and new routing regression pass, with initial waits of
18.93/21.48/31.65 seconds and zero dropped events. The original blocked-launch
branch removed its fixture. Test-only diagnostic `e99ba97` preserves future
failures and bounded job/routing traces without changing payloads, assertions or
deadlines. Its isolated negative repeats in 198.49 seconds and retains a stable
35-file fixture at `/tmp/.tmpVo4svh`, copied read-only under
`/tmp/mb-m6-blocked-launch-diag-5g177s5b`.

At the deadline the coder is Complete, all five nodes have installed sequence 3
and both coding groups, and the owner still has an incomplete activation and an
event-install response pending. The trace has 8,316 events with no drops and no
individual recorded operation longer than 1.91 seconds. Synchronous fixture polls
are not yet timed in that trace. Measure them and the acknowledgement path before
claiming a cause or fix. Keep the 60-second bound, actual activation completion,
all signatures and data checks; no complete-source or installed pass is claimed.
R1/R2/R3/R5/R7 and the separately preserved historical observations remain open.


### 2026-10-26 — Commit volume configuration before live admission

`c442be6` corrects the reproduced runtime volume-registry false acknowledgement.
A probe on `26659ff` acknowledges an ignored 4 MiB to 8 MiB budget update and
raises live admission, while reopening restores 4 MiB. Exact probe source,
executable, baseline library and five-file fixture are retained under
`/tmp/mb-m6-volume-registry-repro-wlv5ibhn`.

Registry publication now verifies exact canonical bytes inside a writer
transaction. Native birth and configuration call the checked publisher within
their enclosing transaction. Candidate budgets, paths, opened/retained catalogs
and drain/reactivation records become live after that commit. Errors retain the
previous live authority and readers. An initialized but unenrolled extra volume
can resume with its original manifest. Data formats, native physical ceilings,
source admission and endpoint authority remain enforced.

Six byte-identical regression sources fail on the archived implementation and
pass with the fix. They cover legacy/managed ignored, aborted and altered writes,
late validation, capacity, original data and acknowledgement evidence, reopen,
new-volume retry, drain and reactivation. All 100 existing volume/native-runtime
cases and 26 disposable Btrfs executions pass: 107 distinct cases in 132
executions. Strict all-Node-test Clippy and formatting pass. `audit.json` verifies
both source archives/executables/dependencies, unchanged regression source, the
original negative and removal of the owned mount/loop/image. This qualifies the
isolated implementation branch. The merged source still needs a complete passing
gate after the restored blocked-launch investigation; no installed qualification
or enclosing R1/R2/R3/R5/R7 closure is claimed. Paged producers stay disabled.


### 2026-10-26 — Keep restart status polling off the swarm executor

The preserved blocked-launch trace led to a measured fixture scheduling defect.
Both status loops synchronously acquired the Node mutex and ran catalog/coverage
queries on the current-thread executor shared by all five swarms. Observational
tracing records 51.92 seconds of executor blocking in the final restored-volume
wait, including 42.65 seconds holding the mutex; healthy-phase polls block it for
22.74 seconds. This prevents queued networking responses from making progress
while the fixture checks their resulting state.

`0585b72` moves the two existing predicates into `node_blocking`, matching the
production workers. The predicates are byte-equivalent after wrapper/variable
normalization, and their deadlines and 100 ms interval are unchanged. The
isolated case passes in 151.92 seconds and the four-thread restart/retry cohort
passes all four cases. Restored polling-to-completion spans are 31.41 and 32.07
seconds. Strict all-Node-test Clippy and formatting pass. `polling-audit.json` in
`/tmp/mb-m6-blocked-launch-diag-5g177s5b` verifies four distinct cases/five positive
executions, exact archived source/dependencies/executables, unchanged predicates,
zero dropped trace events and all 35 preserved negative fixture files.

The demonstrated fixture scheduling defect is corrected. A fresh complete gate
must qualify this correction with the merged volume-registry changes before
installed jobs. This does not explain the separate historical native-capture or
relay-only stalls, close R1/R2/R3/R5/R7, or enable normal paged producers.


### 2026-10-26 — Preserve Store runner timeout and isolate SQL shell scope

The combined ordinary gate on `6926b75` stops at the original 900-second Store
runner bound. Nine completed targets pass all 387 ordinary cases; 567 Store
successes and no failed case are observed, with 55 ordinary cases lacking a
successful status. Node, supplemental and installed stages did not start.
Auxiliary compilation overlapped Store execution, so rerun Store alone under
its same four threads and bound before drawing a contention conclusion. The
independent `negative-audit.json` in
`/tmp/mb-m6-volume-polling-qual-mpx6kjx9` verifies all 455 frozen tracked inputs,
the source archive, all 23 executable physical/hash identities and every
completed target inventory. This remains a failed complete-source prerequisite.

An additional-volume draft independently exposes a live SQL connection defect:
read-only shell queries leave `query_only` enabled, disabling subsequent normal
writers until reopen. A read-only inspection statement can also clear a prior
query-only connection setting. Six regressions reproduce both legacy and native
control/parity cases on the archived baseline while preserving original data
and acknowledgement evidence. Original and final negatives retain 24 fixtures/
60 files, copied read-only under `/tmp/mb-m6-shell-scope-fixy1x0y`.

Isolated code `3e2d84d` restores the previous setting after success/error, with an
unwinding fallback. All six byte-identical final regressions and strict all-
Store-test Clippy pass. The complete Store suite runs alone before merge;
Btrfs and independent artifact/negative audits remain pending. The separate
additional native volume feature is still uncommitted and unqualified. No
complete-source/installed or enclosing R1/R2/R3/R5/R7 closure is claimed.


### 2026-10-26 — Qualify scoped SQL shell inspection

Isolated correction `3e2d84d` passes all 628 ordinary Store cases in 673.95
seconds (675.32 runner), with four threads and the original 900-second bound.
Its six byte-identical new regression sources fail on the archived baseline
and pass after correction, including legacy/native control/parity data and
original acknowledgement evidence. The same six cases pass on disposable
Btrfs: 628 distinct cases in 640 positive executions. Strict all-Store-test
Clippy and formatting pass.

`audit.json` in `/tmp/mb-m6-shell-scope-fixy1x0y` verifies both source archives,
exact dependencies/executables, unchanged regression source, every selected case,
135 process samples and all 24 original/final negative fixtures (60 files).
The owned Btrfs mount, loop association and image are independently absent.
This closes the focused shell connection-state defect. It does not diagnose
the earlier broad Store runner timeout or establish complete merged-workspace/
installed qualification. The additional native parity-volume draft remains
uncommitted and unqualified; R1/R2/R3/R5/R7 and normal paged integration remain
open. No installed jobs ran.


### 2026-10-26 — Create additional native parity volumes with resumable authority

Code `afc3d77` adds explicit managed-Node `create_native_storage_volume` creation/
resume. The signed creation profile fixes its parent, UUID and original I/O
policy/budget before SQL. The original native birth, key and manifest survive
interruption; the checked control-registry transaction precedes live placement.
The caller's private-input guard reaches the actual native main descriptor.
Repeating creation preserves later budgets and drain/retirement state. Existing
legacy/copied/wrong-owner state and excess registry admission reject.

Review reproduced an error that still wrote a fresh conflicting profile into
an empty replacement of a known volume path. The original 19-file fixture,
read-only copy, exact candidate and log remain under
`/tmp/mb-m6-native-volume-replacement-kzzuv5xt`. Final preflight rejects that path
before publication and retains the original pinned payload/acknowledgement.

Nine focused cases and the same nine on disposable Btrfs pass. The surrounding
115-case cohort passes all 106 existing volume, native-runtime and configuration
cases: 115 distinct cases in 133 positive executions. Strict Store/Git/all-
Node-test Clippy and formatting pass. `audit.json` under
`/tmp/mb-m6-native-extra-volume-qual-rn_gatd1/v3` independently verifies all 458
inputs/archive, exact dependencies/executables, unchanged prior assertions/
payloads/deadlines, the preserved negative and owned mount/loop/image removal.
Earlier candidates remain diagnostic evidence; this is focused qualification.

A fresh complete merged-source gate is prepared before installed work. Ordinary
CLI/default policy selection, managed rekey and quiescent old-writer/restore/
host-relocation adoption, host reboot and ownership-bookkeeping/SQL/scratch/
payload/checkpoint funding remain open. Normal paged producers stay disabled;
R1/R2/R3/R5/R7 and the deferred dense 1 TiB/native-platform gates remain open.


### 2026-10-26 — Pass merged native source gate and correct musl ioctl typing

The complete source prerequisite on `30cff18` passes 1,737 distinct cases in
1,811 positive executions, including all 1,725 ordinary cases, three payloads
above 512 MiB, and the provisioned ownership, physical I/O, native volume,
configuration and four native recovery checks. Store passes its original
900-second runner bound and Node passes all 630 ordinary cases. All five
coverage traces complete with no dropped events; the restored predicate spans
36.06 seconds under its original 60-second bound. The independent audit in
`/tmp/mb-m6-native-extra-full-qual-aatzujf4` binds 458 tracked inputs, the archive,
23 executables, 19 target inventories, preserved negative evidence and owned
mount/loop/image removal. The other 125 ignored cases remain unexecuted.

The subsequent pinned static musl build fails in FIEMAP: musl declares an
`ioctl` request as `c_int`, while the allocator passes glibc's `c_ulong`.
`negative-build-audit.json` in `/tmp/mb-m6-installed-30cff18-24xko1zm` verifies
the failed build's immutable source against all 458 qualified inputs. No
installed runtime jobs or filesystem provisioning started. The initial stalled
fetch is separately preserved; importing 775 checksum-verified cached archives
lets the same pinned offline compilation reach the actual source defect.

Correction `faeb44d` preserves the ioctl's explicit 32-bit request bits and
infers the target libc argument type. The existing closed-reflink regression
uses the same portable conversion. All 21 physical I/O cases pass on disposable
Btrfs; strict all-Store-target Clippy, formatting and independent source/archive/
binary/unchanged-assertion/payload/deadline/cleanup audit pass under
`/tmp/mb-m6-ioctl-portability-ra41ei6j`. Corrected musl compilation and a fresh
merged-source prerequisite remain before installed runtime qualification. The
`30cff18` source pass is historical evidence after this correction. Enclosing
R1/R2/R3/R5/R7, normal paged integration and deferred hardware gates remain open.


### 2026-10-27 — Reject cipher mutation during inspection and resume native quotas

`845ac43` corrects the query-only shell's preparation authority. SQLCipher key
and rekey operations execute while preparing their PRAGMAs, before SQLite's
ordinary query-only checks. The authorizer now rejects all six key/rekey names
before those side effects, using SQLite's decoded names for case, quoting and
schema qualification. All 16 targeted shell cases pass, including preserved
original encrypted bytes/keys/acknowledgements, normal followup writes,
read-only cipher inspection and explicitly writable legacy rekey. The prior
24 negative fixtures remain unchanged. This does not explain the separate broad
Store runner timeout.

The managed parity opener also skipped interrupted record-quota adoption.
Two new Node regressions fail on the baseline: default and additional native
volumes reopen with a durable partially scanned quota still Adopting. A shared
Linux opener helper now completes the existing bounded cursor on the admitted
Store before reconciliation, retaining its native lease, key, quota and physical
policy. Identical regressions check original payload/ACK preservation, completed
row accounting, byte-counter growth, ordinary reservation/publication writes and
stable counters on a second reopen.

The ordinary volume/configuration/native-runtime/quota cohort passes 120 cases,
with four top-level cases ignored. Both new managed regressions and the existing
legacy startup regression pass on disposable Btrfs. Strict Node-test Clippy,
formatting and diff checks pass. The audit in
`/tmp/mb-native-quota-restart-3onrxv8l` verifies 459 source inputs, baseline/final
archives and executables, unchanged regression source, case coverage, both
unchanged negative fixtures/30 files with read-only copies, and owned
mount/loop/image removal. These are focused corrections and qualifications.

Next correct R5-VIRTUAL-ZERO-ROUTING before a fresh complete-source prerequisite
and corrected packaged musl qualification. R1/R2/R3/R5/R7, enclosing capacity and
normal paged integration remain open; deferred native-platform and dense 1 TiB
requirements retain their original scope. No installed qualification ran here.


### 2026-10-27 — Route virtual-zero owners before delegated coding

The shared participant-routing helper now includes virtual-zero information
owners. Their bulk input is synthesized locally, but their assigned signatures
and activation participation still require authenticated routes. Current guild/
epoch checks, endpoint admission and Tor policy remain in the same path.

A real native two-file backup supplies the production planner's partially filled
tail lane. The fixture selects a parity participant as coder and the delegator
as verifier before dispatch, retaining the original geometry, inputs, ID and
expiry. It then rebuilds an unpolled coding swarm. On the baseline both
virtual-only remote owner routes are absent before the first RPC; the failure's
original filesystem image and read-only 32-file copy remain preserved. Earlier
fixture candidates remain diagnostic evidence separately.

The identical corrected regression passes on disposable Btrfs in 85.98 seconds.
It requires routes before the first RPC, both assigned owners' actual signed zero
openings, verified transcript replay, completed activation, all remaining coding
lanes and the complete committed format-7 backup. The committed job, verified
checkpoint and transcript survive reopen, and both source files retain their
exact bytes. The case is part of `scripts/git-linux-acceptance.sh`.

All 12 surrounding routing, checkpoint retry, endpoint-authority and Tor-policy
cases pass in 111.85 seconds; their three coverage traces complete with zero
dropped events. Strict Node-test Clippy, formatting, shell syntax and diff checks
pass. `audit.json` at `/tmp/mb-virtual-zero-routing-98lehtdr` verifies 460 source
inputs, baseline/final archives and executables, 41 unchanged linked dependencies,
identical regression source, the narrowly bounded production change, selected
cases, negative evidence and owned mount/loop/positive-image cleanup.

Both named P2 corrections from the 2026-10-26 review are now addressed. Require
a fresh complete-source prerequisite before corrected packaged musl/runtime
qualification. R1/R2/R3/R5/R7, the historical native/relay timeout investigations,
normal paged integration and the deferred hardware/platform requirements remain
open; this focused pass does not close them or enable paged producers.

### 2026-10-27 — Preserve native extent rollback failure evidence

The post-routing full gate on `3158ac1` passed format, packaging harness checks,
strict workspace Clippy and the locked all-target build. Nine ordinary targets
passed 387 cases before Store exceeded its original 900-second bound with 552
recorded successes. Its isolated frozen executable subsequently completed in
890.15 seconds with 633 passes and one failure: native extent exhaustion rolled
back the SQL transaction and preserved the original data, but the following
allocation-accounting call returned `CapacityExceeded`. The failure's original
temporary directory was removed on unwind. Four candidates from the distinct
timeout are preserved with read-only copies; they are not attributed to this
failed case. Source, executable and negative-run audits are retained under
`/tmp/mb-post-routing-full-qual-wd__xz5y`.

The regression now retains its fixture on panic after the connection closes and
logs each tracked file's role, length, allocated bytes and open count when the
accounting call fails. Production allocation and the original test's limits,
payload, assertions and retry remain unchanged. One initial and 20 repeated
physical-I/O cohort runs pass against the original frozen dependency libraries
(19 passed and two ignored per run), with evidence under
`/tmp/mb-native-extent-rollback-uwm1fnw9`. These are diagnostic positives, not a
resolution of the full-run failure or timeout. Complete-source qualification
and corrected installed musl/runtime qualification remain open; no installed
build or runtime has started.

### 2026-10-27 — Reclaim refused native SQL tail reservations

A complete diagnostic Store run before this correction passes all 634 ordinary
cases in 845.16 seconds, under the unchanged 900-second runner. Its exact binary,
per-case timings and source/dependency identities are retained. This positive
does not explain the earlier timeout or the original unpreserved failed case.

Separate ext4 fixtures reproduce a concrete accounting defect in main, journal
and private temporary files. Their fifth extent needs a metadata block, both
when allocating a new unwritten range and when writing into an existing
reservation. All six regressions leave 516 KiB charged against a 512 KiB ceiling
on the baseline. Original negative fixtures remain unchanged with read-only
copies. Native allocation now trims reservations beyond the unchanged file
length on overcharge, using the existing descriptor under SQLite's writer
serialization. It preserves every visible byte, remeasures retained allocation
even after cleanup failure, and returns the original capacity refusal. SHM is
excluded because another connection's mapping/growth can overlap. No ceiling,
payload, durability, existing assertion or acceptance deadline is relaxed.

The identical six regressions and all 19 existing ordinary physical cases pass
on ext4. Btrfs passes its 21 applicable physical cases, including actual ENOSPC,
rollback/retry, stopped reflink refusal and subprocess crash recovery; the six
ext4-specific cases return early there. Strict Store test Clippy, formatting,
diff checks and owned mount/loop/image cleanup pass. Sources, linked dependency
hashes, executables, negative fixtures and case evidence are retained under
`/tmp/mb-native-extent-rollback-uwm1fnw9`. This focused correction does not prove
the fresh complete-source or corrected installed-artifact gates, which remain
required before closing the enclosing M6 requirements.

### 2026-10-27 — Retain post-correction qualification timeouts

The complete-source attempt on `f9aabb6` passes its preliminary format, Docker,
packaging, strict workspace Clippy and locked all-target build checks. Nine
ordinary targets pass 387 cases (including Core 210 and Git 131). Store exceeds
the unchanged 900-second bound after 487 successful statuses and no failed-case
status, leaving 153 of its 640 ordinary cases incomplete. Node, supplemental
and installed jobs never start. The exact frozen executable, run alone with
four workers, per-test timings and the same bound, also times out: 485 successes,
no failed case, 155 incomplete. Neither result establishes a cause or reproduces
the earlier allocation failure. Source/archive and all 23 executable identities
are independently verified against the 461-input snapshot. Four candidate
directories survive each run; their 21 and 19 files remain unchanged with
read-only copies, without claiming case attribution. Evidence and continuation
state: `/tmp/mb-post-extent-full-qual-hagnnduj`.

The isolated timer's report measures only its killed timeout wrapper; do not
use its zero CPU or small RSS values as Store metrics. Direct process sampling
observes a Store high-water RSS of 96,244 KiB before the final unsampled interval.
I/O waits and the absence of recorded CPU throttling are observations, not an
established explanation for either timeout.

The separate native-engine build experiment retains identical source, feature
matrices, all 672 registered cases and Rust debug/overflow checks. Only the
SQLite/SQLCipher package's optimization differs (`-O0` versus `-O2`). Four slow
cases pass 16 A/B/B/A executions, averaging 73.89 seconds for the control and
77.86 for the candidate; the same control varies from 66.97 to 80.80 seconds.
There is no supported benefit, so reject the profile change. Binaries, compiler
producers, profiles, timings and audit are retained under
`/tmp/mb-sqlcipher-dev-optimization-12g42g38`. This experiment qualifies no
acceptance scope. Workloads, encryption, durability, assertions, four workers
and the original deadlines remain unchanged. Complete-source and installed
qualification, the historical failures and the enclosing M6 requirements stay
open; normal paged producers remain disabled.

### 2026-10-27 — Optimize development signature arithmetic with checks retained

CPU sampling of four unchanged slow Store cases produces 8,258 samples without
loss. At least 59.57% of the samples land in Curve25519/vector-arithmetic symbols;
this is a CPU diagnosis for those cases, not whole-suite wall-time attribution.
Evidence: `/tmp/mb-store-cpu-profile-by6juxwv`. The SQLite optimization experiment
above remains rejected. A separate controlled trial optimizes only the
`curve25519-dalek` development package, preserving its backend/features, Rust
debug assertions and overflow checks, the application profile and byte-identical
SQLCipher object. All 16 A/B/B/A executions pass the same four cases, with mean
wall time falling from 66.99 to 29.76 seconds.

The complete candidate Store target passes all 640 ordinary cases in 700.20
seconds with 32 ignored, under the unchanged 900-second bound, four workers and
65,536-descriptor limit. Exact case identities, source and executable hashes,
profiles, backend flags, timings and direct-child resource accounting are
verified under `/tmp/mb-curve25519-dev-optimization-oxxshrpc`. Its recorded maximum
RSS is 149,468 KiB, including descendants reaped by Store. The root Cargo profile
now applies the measured optimization with explicit debug/overflow checks;
cryptographic algorithms, validation work, encryption parameters, durability,
payloads and deadlines are unchanged. Keep the original negatives and incomplete
source attempts as historical evidence. Require fresh complete workspace,
provisioned/bulk and installed-artifact qualification before closing R7; this
standalone target does not close M6 or enable normal paged producers.

### 2026-10-27 — Qualify the merged source and installed native musl runtime

Committed `c37acf2` passes the fresh complete-source gate: 1,739 ordinary cases,
including Store 640 in 695.11 seconds under the unchanged 900-second bound and
Node 632 in 2,020.35 seconds. Original bulk workloads above 512 MiB, provisioned
native/kernel/recovery and virtual-zero routing checks yield 1,752 distinct
cases in 1,834 executions. The independent audit verifies all 461 inputs,
source archive, 23 executables, exact case inventories, five coverage traces
without dropped events, preserved negatives and owned cleanup. Another 125
ignored cases remain unexecuted. Evidence:
`/tmp/mb-curve-dev-full-qual-u3cupign/audit.json`.

The same revision builds offline for musl and passes immutable-source/static
payload/wrapper/alias audit. Installed acceptance passes 27 distinct process
cases in 28 executions and three isolated-PATH Git scenarios. Topology/seed
recovery completes in 877.41 seconds; two distinct relay signer-partition and
coordinator-crash retries complete in 913.19 and 930.57 seconds. Each preserves
and authenticates the original four signatures from a stopped catalog copy,
then commits the same event with all five original signers. Neither interruption
occurs after completed activation, and these positives do not explain the older
historical stall.

Fresh native runtime passes three installed daemon cycles in 56.32 seconds,
preserving the original payload, signed ACK and 12 immutable inputs. Actual
daemon startup completes all three interrupted record quotas; 12 installed
query-only cipher mutations are denied; the original 3 MiB SQL probe hits the
unchanged 2 MiB physical ceiling without publishing a row, then reopens healthy.
Source APIs create the fixture; installed creator/enrollment APIs remain open.

Preserve two harness negatives and their original/read-only image hashes. The
first inventory omitted the existing identity manifest; its correction adds
`identity.toml` without lowering the required count or equality checks. The
second helper expected live object counts from a closed retired volume; the
correction requires closed Retired status and directly checks zero fixed and
variable objects through its authenticated read-only catalog. All original
workloads, quotas, payloads, deadlines and three cycles remain intact. Fresh
native qualification reuses the already passing process matrix only after
binding its exact source/candidate/driver/log identities. The final audit also
verifies 104 installed daemon observations, helper/dependencies, both preserved
negatives and filesystem/network/process cleanup. Evidence:
`/tmp/mb-installed-native-final-v3-2dvlj5af/installed-audit.json`; original build
and process evidence: `/tmp/mb-installed-c37acf2-jwvseexv`; second negative:
`/tmp/mb-installed-native-inventory-v2-dir9gv20`.

Close the focused R7 packaged-musl physical-SQL qualification item. Keep the
enclosing R1/R2/R3/R5/R7, shared resource admission, policy enrollment/rekey,
normal paged production/retention/recovery, historical unexplained failures and
deferred dense 1 TiB/native-platform requirements open. Producers remain disabled.

### 2026-10-27 — Expose explicit native catalog and volume creation through CLI

Linux `init-native` now creates or resumes native catalogs for a previously
initialized, stopped node using the original identity and explicit immutable
control/default-parity policy. `storage create-native` invokes additional-volume
birth through the live daemon. Bounded regular JSON policy files reject unknown
fields; server-side policy/ownership admission remains authoritative. The local
schema preserves raw Unix paths and exact policy fields. Retries return the same
UUID and retain later configuration and retired state. Human-owned daemon
configuration remains explicit; the CLI explains that new paths must be configured
before restart. Documentation includes complete valid policy files and startup
configuration within their ceilings.

Seven CLI and seven wire/schema cases pass. Two process cases exercise genuine
CLI native creation, policy mismatch, live-writer and legacy/identity refusal,
hostile IPC policy, raw-byte volume paths, daemon reopen, retirement, original
data and immutable metadata. Both pass on the default filesystem and owned
Btrfs (40.02 seconds for the Btrfs pair), with cleanup verified. The native Linux
acceptance script now runs these cases on its provisioned filesystem; ordinary
installed process discovery includes them automatically. Strict locked workspace/
all-targets Clippy, format, shell syntax and diff checks pass. The first Clippy
failure was confined to new test assertions allocating paths for comparison;
the corrected borrowed comparisons pass. The audit binds 465 inputs and both
source snapshots and confirms all five process executables remain byte-identical
to the passing Btrfs set. Evidence:
`/tmp/mb-native-cli-enrollment-chd__h8q/v2/audit.json`.

This is explicit source CLI enrollment, not existing-state adoption or a current
installed-artifact qualification. Retain the earlier `c37acf2` source/release
evidence as historical. Complete automatic/default policy, managed rekey, host
reboot, copied/restored/old-writer quiescent adoption, shared resource admission
and normal paged production/retention/recovery, then require fresh combined gates.
R1/R2/R3/R5/R7 and the deferred dense 1 TiB/native-platform requirements remain
open; normal paged producers remain disabled.


Native resource compatibility correction, 2026-10-27: catalog resource policies
could enroll logical main/journal credits exceeding the active native role
ceilings or their shared pool. Three baseline refusal regressions reproduced
acceptance; the fitting policy survived reopen. The shared backing verifier now
reads the original connection's immutable physical limits without opening or
closing descriptors and checks separately rounded 64 KiB main/journal extents
against both role ceilings and their combined pool. Refusal preserves policy
absence, record accounting, original data and ordinary writes through reopen.
Legacy/read-only logical views retain their existing behavior.

Five focused native cases, including the separate-rounding boundary and fitting
reopen, pass within all 42 capacity-policy cases. Physical-I/O cases pass 25 with
two ignored; strict locked workspace/all-targets Clippy, format and diff checks
pass. Baseline sources/executable and three unchanged original/read-only-copy
fixture pairs are retained beside the fixed source archive and logs at
`/tmp/mb-native-resource-backing-xihn3bvq`.

This is a necessary native-pool compatibility bound, not filesystem, SHM,
temporary, scratch, checkpoint-copy or cross-producer reservation. It does not
close shared resource admission, R3, M6, normal paged activation, or the deferred
dense 1 TiB/native-platform qualification requirements.


### 2026-10-27 — Account for WAL-index backing in native resource admission

The native resource check now includes the WAL index needed for the complete
journal declaration, using the bundled SQLite frame/region geometry and separate
64 KiB physical rounding. It rejects insufficient SHM ceilings and combined
main/journal/index pools without changing existing policy encodings or native
limits. The valid baseline reproduces accepting approximately 74 GB of WAL
credits against only 64 KiB of SHM; its fixture/source/executable remain preserved.

All 46 capacity-policy cases pass, including nine native/geometry cases and an
actual 36 MiB protocol-record workload crossing the second WAL-index region,
matching the calculated index length and preserving payloads through reopen.
Physical-I/O passes 25 with two ignored; strict locked workspace/all-targets
Clippy, format and diff checks pass. Retain the initial invalid-policy probe and
the extra-table schema-refusal fixture alongside the corrected ordinary-record
workload. Both original/read-only fixture pairs are unchanged. Evidence:
`/tmp/mb-native-wal-index-qualification` (466-input fixed source archive).

Keep the full shared filesystem/temporary/scratch/payload/checkpoint-copy and
headroom reservation policy, ordinary production integration and R1/R2/R3/R5/R7
open. This necessary database-family compatibility correction does not qualify
the deferred dense 1 TiB or native-platform gates.
