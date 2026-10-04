# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

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
  an eager full copy. Guarded
  link-freeze, VSS, FUSE, and other source backends come after the prototype.
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
- The Git-compatible frontend preserves tracked file bytes exactly. No command
  automatically fixes line endings or applies another content conversion, even
  when the host's Git configuration enables one. Git's `text`/`eol` handling
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
- **Milestone 6 guarded private metadata:** keep the existing signed
  `UserRevision` envelope and encrypt a versioned private format for guarded
  views. Preserve raw Unix path bytes, visible uid/gid, mode, atime/mtime,
  directory length, sparse sector extents, and portable hard-link groups.
  Validate path topology and sector geometry before restore. Keep local inode
  IDs, mount claims, and source-anchor locators outside the signed format;
  restore and reanchor from sector bytes without depending on those old IDs.
  Do not convert guarded entries through the older UTF-8-only private format.
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
  A Git blob imported from an ordinary repository becomes the authoritative
  `B` for our checkout, regardless of that repository's attributes or the
  other client's worktree presentation. Reflinks or guarded hard links may
  share physical extents, but no Git index, object database, pack cache, or
  worktree may retain a second permanent copy merely for compatibility.
  Verify the captured bytes before publishing an index entry or revision and
  the restored bytes before replacing a worktree file. A mismatch is an
  operation failure, never a reason to normalize line endings or run a Git
  filter to make the file match an expected blob. This contract also applies
  to guarded link-freeze and future Windows and macOS backends.
  Keep blocking filesystem work in bounded workers and keep the signed guild
  protocol independent of backend choice.
  The existing reflink root is the first implementation; Git history consumes
  that boundary, and guarded link-freeze/platform capture later implement it.
- `init` associates each Git repository with a stable protected-root ID and
  working-tree location, enrolling and probing a source backend before claiming
  backup protection. Keep the repository marker and Git-facing metadata in an
  app-owned `.mutualbackup` catalog while payload anchors stay in their
  filesystem-specific anchor areas. Exclude that catalog from ordinary tracked
  file scans and protect its reachable graph through encrypted revision metadata
  instead of recursively capturing itself. Reject initialization if that
  protection backend is unavailable; adding a worktree does not silently enroll
  its uncommitted edits. For a guarded FUSE worktree, pin the marked catalog in
  its verified private lower root and hide it from the editable view; the FUSE
  mount does not provide the remount-stable filesystem identity required by
  native catalog and anchor operations.
- Stage a regular file by first creating and durably recording an immutable same-
  filesystem reflink of the user's bytes. Hash that captured file through the
  Git library, record its blob ID, source locator, and index entry atomically
  or with crash-reconcilable intent, and never persist another copy merely to
  satisfy `.git/objects`. A later edit to the working file cannot change the
  staged bytes. Detect concurrent source changes during capture and fail or
  retry rather than recording mixed bytes. An unavailable reflink fails this
  capture path explicitly; the later guarded link-freeze backend must meet its
  own safety probe before offering a hard-link alternative. Preserve sparse
  extents and file identity where the backend supports them. The index records
  the raw captured blob ID: Git configuration and attributes cannot normalize
  line endings or run a clean filter between capture and staging. On Btrfs,
  prove that the staged anchor initially shares physical extents with the
  source file and that a later source edit changes neither the anchor's bytes
  nor its Git blob ID. Equal logical sizes alone do not establish sharing.
  For an unchanged guarded file already frozen by a root anchor, map the Git
  stage to that verified root file with a distinct local object-map ID. Do not
  add a third hard link: the guarded edit journal must retain its exact
  two-link invariant until it detaches the working inode. Keep the root pinned
  for as long as any such Git mapping needs its bytes, and rebind the mapping
  only through a verified backend transition after source-loss recovery. On
  reopen, reconcile guarded stage pins and catalog receipts in both directions;
  a catalog mapping without its node-owned protection must stop startup rather
  than let root retirement or stage replay guess its owner.
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
  writing through that link would mutate the committed blob. A backend may use
  hard links only if its guard first makes the shared inode safely immutable
  and editing detaches it without changing the anchor.
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
- Represent explicit commit protection pins as namespaced Git refs so graph
  export, signed backup, and recovery retain their ancestry without another
  object format. Removing a branch or pin only changes reachability; physical
  deletion waits for the prune/GC gate and every retained revision. The local
  frontend has no implicit reflog protection until a durable reflog is defined.

### Deferred source backends and platform work

- **Guarded link-freeze** creates a private same-filesystem hard link to the
  working inode, records its exact original mode/ACL, uses a short platform
  guard to exclude pre-opened writers and writable mappings, then removes normal
  write/append/truncate permission. A hard link alone is not a snapshot. The
  protection is user-reversible and defends against ordinary accidental
  modification, not a malicious process with the user's authority.
- On Linux, make the long-lived edit guard a versioned FUSE worktree view over
  an inaccessible private source directory on the same filesystem. The
  short-lived lease/fanotify freeze remains the enrollment barrier; the FUSE
  view is the path ordinary applications use afterward. Read-only opens may
  use kernel FUSE passthrough to the frozen source inode. Before returning a
  writable handle, accepting a shared writable mapping, or applying a
  pathname truncate, allocation, or owner `chmod`, the view must run and
  durably finish the existing sparse-detach journal, then pass through only
  the independent editable inode. All simultaneous passthrough handles for a
  FUSE inode must share one live kernel backing registration, including when a
  read-only handle predates detach; keep each handle's source descriptor for
  handle-based truncate and allocation. Rename and unlink preserve the immutable
  anchor without detaching. New files are editable independent inodes, and
  their publication must be replayable across a crash. Atomic replacement must
  keep the replaced file's immutable anchor intact. File `fsync`/`fdatasync`
  must sync the retained inode even after rename, unlink, or replacement;
  directory handles must pin an identity-checked inode so sync still reaches
  it after rename or removal. Propagate storage errors. A mount/daemon failure
  must make the view fail closed, never expose the private source path or
  silently resume through it.
  Probe the mount, passthrough capability, and inaccessible lower path locally
  before guarded enrollment; lack of any required capability is an explicit
  unsupported-backend result. See the [kernel FUSE passthrough design](https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html)
  and [FUSE I/O modes](https://docs.kernel.org/filesystems/fuse/fuse-io.html).
- Before enabling that backend, extend the root probe through hard-link →
  guard/freeze → reject in-place mutation → allow rename/unlink/atomic
  replacement while the anchor survives → sparse detach → exact permission
  restore/edit. If an inode has unaccounted aliases, enroll the whole link group
  explicitly or reject it rather than changing permissions on unknown paths.
  Exercise writes through descriptors and shared writable mappings opened
  before the freeze, truncate and allocation through those handles, and races
  through every known hard-link alias. Record the guard's required privileges
  and fail closed when they are unavailable; an open-time notification or
  permission change alone is not evidence that pre-opened writers are blocked.
- For an in-place edit, use the recoverable local sequence
  `SHARED_FROZEN → COPY_STAGING → PRIVATE_COPY_READY → UNLOCK_PENDING → EDITABLE`.
  Under the guard, make and verify a sparse independent anchor, fsync and install
  it, detach the old hard link, and only then restore the working inode's exact
  permissions. Failure or `ENOSPC` leaves the working inode frozen.
- Evaluate persistent NTFS VSS only after testing service authorization,
  batching, diff-area headroom and eviction, and missing-snapshot reconciliation.
  Native macOS support, portable ACL/xattr handling, and independently chunked
  local packing are also post-prototype work. The Linux FUSE guard above is a
  Milestone 6 requirement for guarded link-freeze enrollment.

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
after in-flight transitions finish. Link-freeze permission restoration must be
journaled before collecting its last anchor. Virtual-zero ranges may be omitted
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

**Current position:** Milestones 0 through 5 have passed. The final Milestone 5
gate passed on exact committed source `53ec2ec`; its earlier review and gate
records below are historical. Milestone 6 is underway: the Git-compatible
local-history and interoperability slices are being built ahead of the already
planned source-backend and platform work. The byte-exact Git policy above and
the complete Milestone 6 gates below remain requirements for closure. Iterate
through the Git command slices while keeping the original backend deliverables
in scope: a command is complete only when its raw-byte, crash/reopen, and
native-anchor storage checks pass; the milestone still requires protected graph
recovery, physical prune, guarded link-freeze, and platform backends.
Before closing the Git phase, re-audit commands implemented before the
byte-exact policy was adopted. Their earlier functional gates do not establish
that add, checkout, merge, restore, pull, and import/export ignore inherited
conversion settings and attributes on every file-content path.
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

### Milestone 6 — Git-compatible local history and additional source backends and platforms

The Git pivot adds local history and interoperability to this milestone; its
original source-backend and platform deliverables remain required. Review each
completed Git command against the byte-exact policy and crash/recovery gates
below, and continue through graph protection, two-way ordinary-Git exchange,
physical reclamation, guarded link-freeze, and platform backends. These work
streams may progress together; the open Milestone 6 items in `TODO.md` remain
part of the closure gate as the plan is iterated. A command being present does
not by itself close its slice.
The native `.mutualbackup` catalog, not a `.git` directory, owns local history;
the same immutable captured bytes serve backup and Git blobs without a second
persistent payload copy. Git compatibility applies to the supported command
syntax and object/pack exchange, while this binary's file-content rule is
strictly byte-for-byte even when stock Git would apply attributes or filters.
Keep those three conditions together as Git work proceeds, and retain the
original guarded-source and platform gates in this milestone's closure test.
On each iteration, choose from all open Milestone 6 gates in `TODO.md`, including
the original source-backend and platform work. For any command or backend that
reads or writes file content, check byte identity from the user's file through
the immutable anchor, Git blob, exported object, and restored worktree. A
line-ending-only change is a real content change; no default, configuration,
attribute, filter, or compatibility option may silently convert it.
Keep the gate list below as the work queue even when a Git slice passes: after
each slice, check which source-backend, guarded edit, platform, recovery, and
physical-prune obligations remain open. A Git command's implementation or an
earlier passing run does not substitute for its byte-exact acceptance on the
current source.

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
- Complete guarded link-freeze with its long-lived Linux edit guard and
  privileged capture/edit/restore and crash-recovery probes.
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
  filesystem destinations; use guarded link-freeze only after its own gate.
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
- Define Git-facing history expiry and prune/GC over refs, index, worktrees,
  retained signed revisions, explicit protection pins, and in-flight work.
  For a guarded repository, enumerate catalog candidates and their stage
  receipts without mutation, then durably fence the exact candidate set in
  node control before deleting any catalog mapping. Replay that fence before
  normal pin/catalog reconciliation; retire each receipt with its mapping,
  release its node-owned file/root pin only after the catalog retirement is
  durable, and finish physical cleanup idempotently. A version-2 virtual
  mapping releases its root pin but never unlinks the root file as if it owned
  a separate payload. A live guarded mount claim still owns a per-file anchor:
  remove its Git mapping and pin, retain a durable deferred-cleanup obligation,
  and delete the physical anchor only after the claim is retired. Provide an
  explicit safe repository-retirement operation that removes an empty private
  Git catalog before guarded-root release. This now uses the explicit
  `mutualgit deinit <repository-id>` command, an exact native-file fence in
  node control, and pre-mount replay; the guarded root remains enrolled until
  its separate release gate passes. The release handoff now has ext4 and Btrfs
  interruption probes with deferred per-file cleanup for separate and in-place
  views; verify that coverage remains valid as guarded Git operations expand.
  A catalog receipt with no node pin must still fail closed unless it belongs
  to an authenticated retirement fence.
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
- Then implement the already planned guarded link-freeze backend, including its
  atomic sparse private-copy transition when the user needs to edit the
  original inode. Preserve file IDs, paths, and metadata without freezing
  directory names or removal. Implement the long-lived Linux FUSE view above
  before selecting this backend for any root; include read-only passthrough,
  writable-open and shared-mapping detach, `chmod` and pathname truncate,
  rename/unlink, replayable new-file creation, atomic replacement, and remount
  recovery. Make enrollment a durable, restartable transition from a private
  lower tree to a supervised view. Separate lower/view and original-path
  handoffs are operational slices; complete the original-path metadata and
  failure gate and data-preserving root removal before closing the guarded
  backend gate. Before removal restores
  ordinary ownership, detach every live lower file from immutable anchors
  under a stopped-view fence, then durably hand its current namespace and
  visible metadata back to the user. Never expose a raw hard
  link between an editable worktree and an immutable anchor.
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
- Close guarded link-freeze separately with its full atomic edit/failure and
  anchor-recovery probe, including `ENOSPC`, unknown hard-link aliases, and
  restart at each permission and sparse-detach transition. Before enabling a
  long-lived edit guard, prove that ordinary reads do not trigger eager detach
  while every write path remains blocked until a private anchor is durable,
  including after owner `chmod`, pathname truncate, and a daemon restart.
  A pre-opened read-only descriptor to a user-owned lower inode can call
  `fchmod` and reopen `/proc/self/fd` for writing after the short capture guard
  ends; hiding the lower pathname is insufficient. Before enrollment, make
  all lower inodes inaccessible to that owner through retained descriptors,
  including directories and new files, while preserving user-visible modes
  and ownership in protected virtual metadata. Prove the anchor remains exact
  through pre-opened file and directory descriptors, permission changes,
  writable reopen attempts, edit detach, crash, and remount.
  Linux `FAN_PRE_ACCESS` reports both read and write access with a byte range;
  that event alone does not identify an edit. Keep enrollment gated until the
  full access decision and failure behavior pass a privileged local probe.
- Close each listed platform backend only after its own capture/edit/restore,
  metadata fidelity, application-consistency, source-loss recovery, and raw Git
  add/checkout/interoperability gate under conversion-inducing host settings.
  Milestone 6 closes only after the Git, guarded-link-freeze, and listed
  platform gates.

Use this dependency order for the Git work: versioned source boundary and native
Git object access; byte-exact local history and worktrees; encrypted graph
protection and recovery; ordinary-Git exchange in both directions; reachability-
based expiry and physical reclamation. Continue guarded link-freeze and the
listed platform backends whenever their prerequisites are ready, rather than
deferring their open `TODO.md` items until every Git slice is closed. Keep the
Git byte-policy and relevant crash/recovery checks in each slice. Milestone 6
closes only when all Git, original source-backend, and platform gates above pass.

### Milestone 7 — release candidate and compatibility freeze

- Fuzz every parser and state machine; property-test recovery and authorization;
  test partitions, malicious peers, corruption, remounts, clock changes, huge
  trees, disk/WAL exhaustion, interrupted upgrades, and every incomplete object
  transition. Measure and cap tasks, queues, memory, CPU, connections, relay/DHT
  work, bandwidth, and storage amplification.
- Freeze the documented Git-command subset, byte-exact file policy, Git object
  and transport interoperability, source-backend versions, branch/reflog
  retention, and prune semantics only after cross-version migration and
  source-loss recovery gates pass. Measure both logical and physical Btrfs
  space across add, checkout, branch retention, import/export, and prune.
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
