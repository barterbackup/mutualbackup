# Product TODO

## Milestone 2 corrective follow-up

The latest source-only review found the current defects below. They are faults
in implemented behavior or in Milestone 2's claimed exit assurance, not delayed
features. Fix and remove them before beginning Milestone 3.

- Reject any overlap between a recovery-string output and `data_dir` before
  writing either path. With an existing empty directory,
  `init --data-dir DIR --seed-file DIR/seed` installs the seed and then rejects
  the now-nonempty directory. In the reverse direction, an absent
  `--seed-file /tmp/node --data-dir /tmp/node/state` creates `/tmp/node` as a
  file and makes the child directory impossible. Identical retries remain
  wedged. Resolve path topology safely even when the leaf is absent, and cover
  equal paths, both nesting directions, `..` components, symlink aliases, and
  matching or conflicting existing outputs without mutation on rejection.
- Resume locally installed cold recovery before consulting the DHT again.
  Still-staged recovery rows are reused, but `recover_from_dht` unconditionally
  starts provider discovery and certification. Once checkpoint installation
  has moved the sectors into their regular stores and cleared staging, a crash
  before or during restore makes complete local state and its durable recovery
  job depend on three peers again. The Docker lab compounds this by requiring
  three live survivors before it permits any pending reinit to resume. Make
  both layers recognize locally resumable state first, and add interruption
  coverage which removes the recovery quorum before retrying owned building,
  ready, published, and complete states.
- Bound and reconcile durable cold-recovery attempts. Partial 64 KiB shard rows
  are deleted only after successful installation of their exact checkpoint;
  moving through newer certified heads can strand catalog-scale rows for every
  failed head. Per-checkpoint recovery jobs can likewise leave hidden build
  trees when another head supersedes them. Define durable active/pinned attempt
  ownership, preserve work that can still resume, and transactionally collect
  superseded rows and application-owned trees. Exercise repeated partial heads
  under a deliberately small space/attempt bound.
- Cancel or explicitly bound abandoned outbound peer requests. Shard recovery
  starts every non-target fetch and stops polling after any three valid shards;
  recovery-head validation similarly returns after the first certifying state
  fetch. In both cases the dropped futures leave their requests in the event
  loop's unbounded `pending_requests` map until response or timeout. Many coding
  groups with one slow fourth holder can accumulate one live request per group,
  while a candidate race can abandon many at once. Make caller cancellation
  observable by the event loop or enforce a global permit owned by each pending
  request until terminal cleanup, and cover both paths at their configured
  bounds.
- Retain accepted signed-DHT-record sequence and hash state across refreshes and
  retries. Both endpoint and recovery-bundle selection are stateless per query,
  so a later response containing only sequence N-1 rolls back sequence N, while
  two different sequence-N records returned on different polls evade fork
  detection. The selectors can also miss a fork at a lower sequence in one
  result after selecting a higher record. Key durable observations by record
  kind, publisher, and recovery subject where applicable; compare every valid
  same-sequence hash before selecting the highest. A successful but empty
  endpoint lookup must not clear the last unexpired signed address set because
  DHT absence is not an authenticated revocation. Exercise endpoint and bundle
  rollback/forks, empty refresh, failed-recovery retry, and restart cases.
- Isolate pre-authority recovery addresses from the shared learned-endpoint
  cache. Candidate endpoints are inserted before their guild/checkpoint
  authority is established and remain for up to 15 minutes when validation
  fails, potentially past the signed locator's own expiry. Repeated hostile
  provider sets can exhaust the 1,024-peer cache and reject legitimate recovery
  peers. Use an attempt-owned scope with unconditional cleanup, or promote only
  certified candidates into bounded retained state.
- Keep relay authorization synchronized independently of outbound DHT
  maintenance. A relay server initializes admission from the active guild at
  startup, but its only later synchronizer is coupled to DHT refresh. When
  `enable_dht_maintenance = false`, forming or installing the guild in the
  running daemon never updates that set, so every member is rejected until a
  restart. Notify the network on guild-state transitions or run a separate
  lightweight membership synchronizer, and cover the documented server-only
  configuration.
- Reconcile Btrfs mount ownership and mode on the already-mounted branch of the
  Docker lab. Interruption after `mount` but before ownership and mode
  normalization leaves the fresh filesystem with the wrong owner or mode; the
  next `up` sees a valid mount and skips those repairs. This can block the
  unprivileged node or leave its host tree less private than promised. Make
  every successful `ensure_filesystem` return enforce the expected UID/GID and
  mode, with interruption regressions at both boundaries.
- Replace mount-instance identifiers in durable filesystem identity. A
  protected root persists `(st_dev, statx mount_id)` and exact checks in backup
  and watcher paths reject it after an ordinary remount; Docker `down`/`up`
  recreates both the Btrfs mount and container mount namespace. Recovery also
  persists `(st_dev, st_ino)` for ready, published, and complete targets, while
  moved-anchor discovery filters on a recorded `st_dev`; loop reallocation can
  invalidate both. Use a remount-stable filesystem identity and application
  markers/object IDs for durable ownership, retaining mount IDs only as live
  transition guards. Fault-inject `down`/`up` with changed loop allocation,
  then cover backup, moved-anchor discovery, and every resumable restore state.
- Canonicalize and validate the Docker lab root before deriving its checksum or
  mutating anything below it. The current `/` and repository-root exclusions
  compare only the lexical string, so `..` components or symlink aliases bypass
  them while later mount, image, and reinit deletion paths resolve to the
  protected location. Define an absent-leaf and ancestor-symlink policy, reject
  canonical aliases of unsafe roots, and cover traversal and symlink cases
  without creating, mounting, or deleting anything on rejection.

## Later guild geometry and coding protocol

- Treat failure domain as a human-supplied correlation claim, never a generated
  guild index. Equal claims mean that nodes may fail together—for example due
  to a shared disk, host, site, power source, operator, or provider—and no
  coding group may place two shards in a matching hard domain. Keep logical
  ordering separate and deterministic from authenticated Node IDs. Bind each
  accepted group to the member/domain snapshot used at placement so a later
  move, recovery, or relabel cannot reinterpret old protection; certify a new
  claim before using that node for new placements. Larger guilds may contain
  several members with the same claim.
- Keep ordinary guild membership symmetric in protocol authority and placement
  eligibility: every member may publish owned information, store assigned
  parity, and sign according to the guild policy. Coordinator, relay,
  bootstrap, and storage-only operation are replaceable capabilities rather
  than permanent membership classes.
- Preserve deterministic, merge-friendly coding affinity while removing
  placement skew. A versioned geometry records its code profile, canonical
  ordered information hosts, and deterministic parity-row-to-host mapping over
  distinct failure domains. Reuse that exact geometry for long aligned runs of
  compatible adjacent sectors so information and parity ranges can coalesce
  one-for-one. Apply capacity, availability, and accounting fairness when
  choosing the information hosts for a new geometry lane or coarse batch—not
  by rotating or shuffling roles independently for each sector. Keep every
  accepted geometry explicit so recovery never reruns the scheduler.
- Split checkpoint sequencing from bulk coding execution. Keep the certified
  guild coordinator responsible for the durable job and authenticated state
  transition, but delegate each immutable, hash-identified geometry lane or
  bounded batch to an ephemeral coding coordinator with no checkpoint
  authority. Rank authenticated live candidates by the estimated cost of all
  input and output paths, strongly preferring a member of the coding group with
  proven direct connectivity to all sources and destinations; an information
  or parity participant saves one complete transfer, and a parity holder can
  store one output locally. For a `k+m` group this reduces bulk shard transfers
  from holder-side recomputation's `k*m` to `k+m`, or `k+m-1` when the
  coordinator is a participant. Direct and hole-punched paths are preferred,
  but relay or onion fallback must retain availability. Candidate choice and
  retries never affect group IDs, roots, or checkpoint bytes.
- Give that coding coordinator a narrow, expiring, plan-scoped delegation. It
  streams each owner-encrypted information range exactly once, verifies its
  committed root, computes parity with bounded memory, discards unassigned
  payload, and sends only each deterministic parity row to its holder. Persist
  attempts at the checkpoint coordinator and make timeout/failover recompute
  the identical plan; late and duplicate uploads converge through idempotent
  holder operations. Reserve destination capacity before carrying the bulk
  input traffic.
- Replace holder-side full parity recomputation with a durable two-role coding
  attempt. The certified checkpoint coordinator delegates one immutable plan to
  distinct ephemeral coding and verification coordinators. The verifier may be
  any reachable guild member except that attempt's coding coordinator;
  reachability has low weight because verification traffic is small. Before
  encoding, the verifier commits to hidden random challenge material. The coding
  coordinator then receives every information range once, signs the ordered
  input and output roots, and sends only each parity row to its holder. Holders
  persist the root-bound bytes as genuinely `STAGED` and sign storage receipts;
  only then may the verifier reveal a challenge derived from its nonce and the
  frozen plan, roots, and receipts.
- Add a canonical range commitment and sampled-RS transcript. The current flat
  `BLAKE3(bytes)` sector root cannot prove a 16-byte range. Specify a
  domain-separated Merkle/root suite, aligned sampling and proof-leaf sizes,
  length and padding rules, proof encoding, and golden vectors. If a proof opens
  a larger leaf, transfer and check that complete leaf; a Merkle path cannot
  authenticate a bare substring that the tree did not separately commit. Every
  information and parity holder returns the same challenged range with a signed
  Merkle opening bound to the plan, attempt, root, shard index, verifier, and
  challenge. Use one uniformly selected aligned 16-byte offset across every
  shard, with 16-byte Merkle leaves, so each holder sends exactly that piece and
  its path. The verifier receives no complete shard: it checks only those
  openings and evaluates the 16-byte RS equation for each parity row
  independently, never recomputing a parity sector. It then publishes all
  openings in a signed, replayable audit report. Every checkpoint signer
  verifies that transcript rather than trusting a pass/fail bit. Keep
  staged-storage receipts, sampled-coding evidence, and final activation as
  separate protocol facts.
- State the sampling guarantee accurately. Among the 4,096 aligned 16-byte
  ranges in a 64 KiB shard, one uniformly random sample catches one bad range
  with probability only `1/4096`; its Merkle proof authenticates that sample but
  does not improve coverage of unsampled bytes. Treat this as a deliberately
  probabilistic check suited to widespread coding faults, never as proof that
  the entire codeword is valid. Pin the general miss probability and intended
  threat model in protocol tests, retain independently challenged periodic
  audits, and choose a stronger audit policy or separately reviewed proof if
  sparse adversarial corruption must be excluded.
- Make audit failure and cleanup evidence-driven. If all information openings
  and a parity opening are valid but that parity row's RS equation fails, the
  coding coordinator signed a bad output root; an invalid signed opening
  attributes the bad response to that shard holder; and a false verifier report
  is exposed by replaying its transcript. Silence or a timeout establishes only
  unavailability. Any missing confirmation aborts the complete attempt: retain
  compact attributable evidence where it exists, remove every uncommitted
  staged parity sector from that attempt, and repeat the full information upload
  with a fresh operation ID, coding coordinator, verifier, and hidden challenge.
  Never delete already active protection until a verified replacement is
  committed.
- Decouple the signed guild roster from coding geometry. Membership epochs may
  admit more than five members, but each old group retains its explicit profile,
  ordered holders, and at-placement domain binding. Choose the profile and
  participants for new geometry from the current roster, measured simultaneous
  availability, desired failure tolerance, storage overhead, and repair cost;
  do not hard-code `3+2` merely because it was the five-member prototype, and
  do not mechanically span every guild member either. Addition affects future
  placement immediately. Removal or relabel prevents new assignments and queues
  repair; optional conversion of sound old groups is lower-priority background
  migration using create-and-verify before the authenticated state switch.
