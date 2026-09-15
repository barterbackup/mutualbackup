# Product TODO

## Milestone 4 follow-up source review — corrected 2026-09-15

Source review of `e663c49..8411f7d` found the remaining blockers below. The
2026-09-14 test results remain historical evidence for the cases they exercised;
they do not cover these combined failure schedules. This review ran no builds,
tests, or runtime probes. Close these findings and the correction gate before
advancing to Milestone 5.

- [x] **M4-15 / P1 — Preserve an uncommitted writer across unrelated checkpoints.**
  `writer_incarnation` accepts a pending incarnation only while its original
  `base_checkpoint` equals the current guild head, then permanently fences it
  otherwise (`crates/mb-node/src/node.rs:2154`). That base is never updated.
  If a first capture fails after the writer is persisted, another owner's
  backup advances the shared checkpoint without changing this owner's fence
  (`crates/mb-node/src/network/p2p.rs:6960`). Every later local backup fails,
  including after reopen, although no replacement writer was certified.
  Distinguish unrelated checkpoint progress from actual supersession. Cover
  interrupted first capture and recovery takeover, another owner's commit,
  retry/reopen, and continued rejection of a truly superseded writer.
- [x] **M4-16 / P1 — Migrate pending version-1 capture intents.**
  `CaptureIntent` inserts `captured_change_sequence` into its positional
  postcard encoding (`crates/mb-node/src/snapshot.rs:226`), while startup
  decodes only the new shape and requires version 2 (`snapshot.rs:243`). A
  pending capture written before `d1857b5` cannot be reconciled after upgrade;
  `Node::open_locked` propagates the error before starting service
  (`crates/mb-node/src/node.rs:595`). Add an explicit legacy decoder/migration
  that preserves owned capture cleanup and treats the unknown dirty generation
  conservatively. Cover upgrade with an interrupted version-1 capture.
- [x] **M4-17 / P1 — Isolate corrupt pending writes during startup.**
  A publication interrupted after READY commit leaves `volume-write-intent`
  durable (`crates/mb-node/src/volume.rs:671`). If that object's payload is
  corrupt, the database can still open, but `reconcile` propagates its
  `load_ready` integrity error (`volume.rs:690`). Startup requires this step
  to succeed (`crates/mb-node/src/node.rs:597`), so healthy storage and the
  scrub/repair controls become inaccessible. Quarantine/report the failed
  volume while retaining reconciliation evidence. Cover interruption after
  object commit, corruption, healthy replacement, and daemon reopen.
- [x] **M4-18 / P1 — Keep corrupt retired shards from blocking GC and startup.**
  `remove_unreachable` verifies payload bytes before deleting a certified
  unreachable object and propagates corruption even on a Failed volume
  (`crates/mb-node/src/volume.rs:537`). Retiring its group and advancing beyond
  the GC grace period makes checkpoint completion fail at
  `crates/mb-node/src/node.rs:3179`; every restart repeats GC at `node.rs:609`.
  Safely delete or defer the corrupt unreachable object using certified
  identity without making peer/control startup depend on valid obsolete
  payloads. Cover corruption, retirement, grace-period advance, and reopen.
- [x] **M4-19 / P1 — Reconcile relocated volumes by durable UUID before initialization.**
  A newly configured path enters `initialize_volume` before the existing UUID
  is checked (`crates/mb-node/src/volume.rs:339`). Its manifest branch resets
  Online/configured state and creates a missing database (`volume.rs:940`).
  Moving an absent established volume to a new path therefore bypasses database
  loss detection while retaining old receipts. Moving a Retired volume also
  silently reactivates it. Merge the discovered manifest with durable UUID
  state before any creation or activation. Cover a relocated established
  manifest with lost database and a relocated completed drain.
- [x] **M4-20 / P2 — Bound automatic-backup errors on UTF-8 character boundaries.**
  The new scan-error handler calls `message.truncate(512)`
  (`crates/mb-node/src/node.rs:908`). A failing descendant with a long Unicode
  path can place byte 512 inside a character and panic while holding the Node
  mutex. The task error propagates through `crates/mb-node/src/automation.rs:127`
  and terminates the daemon at `cmd/mutualbackup/src/bin/mutualbackupd.rs:151`.
  Apply character-safe bounds to scan and completion errors; test long Unicode
  failure paths with persisted blocked/retry status and continued service.
- [x] **M4-21 / P2 — Make emergency-copy classification recoverable after interruption.**
  `install_repaired_shard` commits the payload and volume receipt before
  separately writing its proof and emergency marker
  (`crates/mb-node/src/node.rs:2445`). A crash before the marker leaves an
  emergency information payload that healthy-group cleanup never enumerates
  (`node.rs:2484`) and retirement never schedules for volume GC (`node.rs:3065`).
  Volume reconciliation repairs receipts only. Persist/reconcile the repair
  classification across these commits. Cover interruption before proof/marker,
  reopen, restored assignments, retirement, and complete space reclamation.
- [x] **M4-22 / P2 — Keep GC work until every migration duplicate is collected.**
  Interruption after migration destination commit leaves both source and
  destination copies (`crates/mb-node/src/volume.rs:810`). GC deletes only
  the receipt-selected destination and returns success (`volume.rs:548`),
  after which its durable candidate is removed
  (`crates/mb-node/src/node.rs:3199`). The source survives; resuming its drain
  republishes already-collected data and a receipt with no cleanup candidate.
  Collect every duplicate or retain per-volume cleanup obligations, including
  unavailable sources. Cover migration interruption followed by retention/GC,
  reopen, source return, and resumed drain.
- [x] **M4-23 / P2 — Reuse repaired destinations when draining a returned volume.**
  Replacement repair stores the payload with an empty acknowledgement
  (`crates/mb-node/src/volume.rs:598`). If the original volume returns and is
  drained, migration retains the replacement receipt but republishes using the
  original nonempty acknowledgement (`volume.rs:788`, `volume.rs:805`). The
  database rejects the valid destination because those bytes differ
  (`crates/mb-store/src/database.rs:1503`). Reuse the verified destination while
  preserving repair/publication acknowledgement semantics. Cover source loss,
  replacement repair, original return, and completed drain at exact capacity.
- [x] **M4-24 / P2 — Report failed volumes even when their metadata is unreadable.**
  Scrub marks a database Failed on a read error but retains its store
  (`crates/mb-node/src/volume.rs:730`). Status still propagates errors from
  `used_bytes`, allocation, free-space, and object-count queries
  (`volume.rs:399`), so an unreadable table page or unavailable filesystem
  prevents reporting every volume. Return the failed entry with unavailable
  measurements and its error while preserving healthy entries. Cover metadata
  corruption after open, beyond the existing payload-only corruption fixture.
- [x] **M4-25 / P2 — Reserve physical database growth rather than payload length alone.**
  Placement compares only `object.bytes.len()` against free space minus
  headroom (`crates/mb-node/src/volume.rs:621`, `volume.rs:637`). A new 64 KiB
  object also requires row metadata, encrypted pages, and WAL space
  (`crates/mb-store/src/database.rs:1740`, `database.rs:2245`). With no reusable
  pages and free space equal to headroom plus 64 KiB, placement passes but
  consumes the reserve or fails during publication. Account conservatively for
  physical database/WAL growth. Cover the actual allocation boundary, including
  shared-filesystem control work, instead of only headroom exceeding all free
  space.
- [x] **M4-26 / P2 — Step incremental vacuum to completion before reporting reclaim.**
  Reclaim calls `PRAGMA incremental_vacuum` through `execute_batch`
  (`crates/mb-store/src/database.rs:1321`, `database.rs:1336`). The pinned
  rusqlite 0.37 implementation steps each statement once; bundled SQLCipher
  emits a result row after each vacuumed page. Each call therefore processes
  at most one page, leaving most of a deleted 64 KiB object's allocation behind.
  Consume the statement to completion and checkpoint afterward. Verify that
  reclaim drains the freelist and returns the expected allocation; the current
  test only checks for any decrease (`database.rs:3567`).
- [x] **M4-27 / P2 — Resume fresh-volume initialization after the empty database commit.**
  Initialization persists the manifest first
  (`crates/mb-node/src/volume.rs:986`), then commits an empty database via
  `VACUUM` before starting the application-schema transaction
  (`crates/mb-store/src/database.rs:1733`). A crash there leaves a manifest and
  nonempty database without tables. Retry skips creation because the file
  exists (`volume.rs:952`) and established opening rejects it (`database.rs:1228`),
  so the configured external volume prevents startup repeatedly. Persist
  authenticated initialization state distinct from established-data loss. Cover
  interruption before/after schema and registry commits and restart convergence.

- [x] **Run a new Milestone 4 correction gate after M4-15 through M4-27.**
  Commits `8162ffc`, `99d8ad5`, and `21486e4` close the combined failure and
  upgrade schedules. On 2026-09-15 the exact corrected tree passed locked
  workspace tests and warning-free workspace Clippy. A disposable local Btrfs
  filesystem passed the complete reflink/network gate, including the version-1
  capture migration, real shared-filesystem headroom boundary, generation-2
  seed recovery, repeated multi-owner QUIC backup, and five-daemon seed/DHT
  recovery after source and holder loss. Docker-controller safety and the real
  NAT-PMP lifecycle gate also passed. All compilation and execution were local;
  no remote compilation server was used.

## Milestone 4 initial review findings (prior correction record)

Source review of `7b1114a..b8ffc90` on 2026-09-14 reopened Milestone 4.
The findings below follow source paths and durable-state transitions; no builds,
tests, or runtime probes were performed for that review. The corrections in
`d1857b5` through `83ebf83` were marked complete and passed the recorded local
gate. The follow-up findings above identify remaining cases in that corrected
implementation; Milestone 4 is reopened until they are resolved.

- [x] **M4-01 / P1 — Allow seed recovery without historical checkpoints.**
  Recovery downloads the selected head, but `reconcile_garbage_collection`
  unconditionally loads its parent (`crates/mb-node/src/node.rs:2964`).
  `install_recovered_checkpoint` calls GC after durably installing that head
  (`node.rs:4060`), so blank-state recovery at generation 2 or later fails
  before file restoration; `Node::open_locked` repeats the failure on restart
  (`node.rs:593`). Make GC conservative when historical certificates are
  absent without weakening live-object protection. Verify seed-only recovery
  at generation >= 2, completed restoration, and close/reopen with only the
  selected certified head available locally.
- [x] **M4-02 / P1 — Keep a superseded writer fenced.**
  `writer_incarnation` silently replaces an existing superseded incarnation
  with `latest_epoch + 1` (`crates/mb-node/src/node.rs:2101`), while checkpoint
  reconciliation adopts the recovered head and marks the old machine's root
  dirty (`node.rs:2514`, `node.rs:2897`). Its next ordinary or automatic backup
  can therefore take ownership back and publish stale filesystem contents.
  Distinguish fresh recovery/explicit takeover from a fenced existing writer.
  Cover two independent data directories sharing a seed: after recovery
  establishes the replacement writer, backups and restarts on the old machine
  must remain fenced until an explicit takeover.
- [x] **M4-03 / P1 — Keep peer service online when automatic scanning fails.**
  `poll_automatic_backup` propagates root enumeration/metadata errors
  (`crates/mb-node/src/node.rs:888`, `node.rs:972`). The automatic worker
  propagates them (`crates/mb-node/src/automation.rs:15`), and the daemon's
  top-level select shuts down the node
  (`cmd/mutualbackup/src/bin/mutualbackupd.rs:151`). With automation enabled,
  a missing source directory or an entry disappearing during a scan can stop
  service instead of leaving a dirty, blocked root. Persist the reason and
  retry safely. Cover missing/unreadable roots and scan races while checking
  that peer/control service and later automatic reconciliation continue.
- [x] **M4-04 / P1 — Persist the captured dirty generation with the revision.**
  Capture commits the immutable revision and head first
  (`crates/mb-node/src/snapshot.rs:625`); `prepare_protected_backup` records
  `revision-root-change` afterward (`crates/mb-node/src/node.rs:1676`). A crash
  between these writes, followed by a source edit and retry, reuses the old
  snapshot but records the new dirty generation. Committing it then clears
  uncaptured changes (`node.rs:2833`); a missing generation also permits
  clearing. Bind the original generation to durable capture/retry state and
  treat missing evidence conservatively. Inject this interruption, edit the
  source, reopen/retry, and verify the root stays dirty until a new capture
  includes the edit.
- [x] **M4-05 / P1 — Use a verified emergency copy of the requested shard.**
  Audit reconstruction clears the target even when it already contains a
  verified emergency copy (`crates/mb-node/src/network/p2p.rs:6205`). With only
  indices {0,3,4} available and index 0 present only as an emergency copy, this
  leaves two inputs and aborts repair. Recovery/restore also excludes the
  target from emergency lookup (`p2p.rs:6586`), then requires three other
  indices. Consume verified target bytes directly. Cover audit, restore, and
  recovery with each emergency index as the target and exactly three surviving
  indices, including emergency information shards.
- [x] **M4-06 / P1 — Isolate corruption from healthy copies and status.**
  Scrub marks a corrupt volume Failed but retains its store
  (`crates/mb-node/src/volume.rs:649`). Local and pooled network readers stop
  on its first integrity error (`volume.rs:446`,
  `crates/mb-node/src/node.rs:507`), so it can mask a verified replacement on a
  later volume. Status also verifies every payload and fails on the corruption
  (`volume.rs:380`). Preserve integrity errors while trying healthy copies,
  and keep failure/status reporting available. Cover corruption, scrub,
  replacement repair, local/network reads, and restart with either ordering
  of source/replacement UUIDs.
- [x] **M4-07 / P1 — Retire network readers before declaring a disk removable.**
  P2P snapshots the volume reader configuration at startup
  (`crates/mb-node/src/network/p2p.rs:1209`); checkout reuses pooled handles or
  that fixed configuration (`crates/mb-node/src/network.rs:197`). Migration
  drops only the writer handle before reporting "safe to remove volume"
  (`crates/mb-node/src/volume.rs:753`). Pooled readers retain the old filesystem;
  fresh readers still open every old path before serving even control reads
  (`crates/mb-node/src/node.rs:408`). After detach this can fail unrelated peer
  reads or recreate an empty database at a writable exposed path. Refresh
  membership, evict retired handles, and use noncreating reader opens. Cover
  live drain, physical detach, and continued profile/checkpoint/parity reads
  without restarting the daemon.
- [x] **M4-08 / P1 — Detect loss of an established parity database.**
  `open_volume_store` verifies the manifest but opens a missing database with
  creation enabled (`crates/mb-node/src/volume.rs:921`,
  `crates/mb-store/src/database.rs:2113`). A database truncated to zero bytes is
  also initialized under the old UUID (`database.rs:1614`). Existing receipts
  survive, while the volume can appear Online with zero objects. Distinguish
  first initialization from reopening acknowledged storage and record loss
  instead of silently recreating it. Test removal and truncation of only an
  established database while retaining its manifest and control receipts;
  require explicit replacement/reconciliation and visible degradation.
- [x] **M4-09 / P2 — Migrate repaired and emergency objects.**
  `store_repair` stores valid objects with an empty acknowledgement
  (`crates/mb-node/src/volume.rs:536`), but migration always calls
  `load_acknowledgement` (`volume.rs:720`), which rejects empty values
  (`crates/mb-store/src/database.rs:1484`). Any such object blocks completion
  of a drain. Preserve the distinct acknowledgement semantics of ordinary
  publication and repair, and cover migration of assigned repairs plus
  emergency information and parity objects.
- [x] **M4-10 / P2 — Resume migration without reserving duplicate capacity.**
  An interruption after destination commit leaves both copies and a receipt
  naming the destination. Retry deletes that receipt
  (`crates/mb-node/src/volume.rs:729`) and demands space for another whole
  object (`volume.rs:574`) before discovering the already verified copy.
  Reuse committed destination state. Cover interruption after destination
  commit with a destination budget exactly equal to the copied payload,
  followed by reopen/reconcile and successful drain; the existing interruption
  fixture allows twice that capacity (`volume.rs:1473`).
- [x] **M4-11 / P2 — Preserve completed drains through daemon configuration.**
  Migration persists Offline/configured=false (`crates/mb-node/src/volume.rs:753`),
  but daemon startup reapplies the TOML volume paths
  (`cmd/mutualbackup/src/bin/mutualbackupd.rs:563`) and `configure` makes the
  drained volume Online again (`volume.rs:313`). A disk declared removable can
  accept new writes after restart. Preserve retirement until explicit
  reactivation. Test the actual open-and-configure startup sequence with
  unchanged configuration, not only `StorageVolumes::open`.
- [x] **M4-12 / P2 — Complete emergency-copy cleanup across checkpoint changes.**
  Cleanup requires the copy's creation checkpoint to equal the latest hash
  (`crates/mb-node/src/node.rs:2441`), so advancing the checkpoint while keeping
  the group prevents cleanup after assigned protection returns. Separately,
  retiring an information role schedules only `gc-sector` (`node.rs:3003`),
  which deletes a control recipe rather than its emergency volume payload
  (`node.rs:3095`). Such retired copies retain their bytes, receipts, proofs,
  and markers indefinitely. Validate cleanup against the current certified
  group/root and collect emergency copies of every role after the certified
  grace period. Cover checkpoint advance, assigned repair, group retirement,
  restart, and capacity reclamation for information and parity copies.
- [x] **M4-13 / P1 — Bound memory for storage status and migration.**
  `ready_objects` collects all full shard payloads into one vector
  (`crates/mb-store/src/database.rs:1241`). Both status and migration use it
  (`crates/mb-node/src/volume.rs:386`, `volume.rs:713`), so a routine status
  request can exhaust daemon memory when stored parity exceeds RAM. Count
  metadata without loading payloads and migrate verified objects in bounded
  batches. Verify memory bounds independently of total stored volume size.
- [x] **M4-14 / P2 — Implement physical-space accounting and reclamation.**
  The volume requirements in `plan.md` distinguish logical quota from physical
  allocation and require reclaim plus operational headroom. Current accounting
  only sums payload lengths (`crates/mb-store/src/database.rs:1231`), placement
  subtracts logical headroom (`crates/mb-node/src/volume.rs:567`), and collection
  only deletes rows (`database.rs:1348`). There is no implemented physical-space
  accounting or database reclaim operation. Track allocated database/WAL space
  and available filesystem space, preserve recovery/GC headroom, and provide
  controlled reclaim. Cover deletion/reclaim and a nearly full filesystem
  independently of the configured logical quota.

- [x] **Re-run the Milestone 4 closure gate after corrections.** On 2026-09-14,
  the exact corrected source tree passed locked workspace tests and warning-free
  workspace Clippy. A locally provisioned disposable Btrfs filesystem passed
  `scripts/reflink-acceptance.sh`, including capture interruptions,
  generation-2 seed recovery over QUIC, close/reopen and GC, and real
  five-daemon recovery from seed and DHT after source loss. Focused regressions
  cover corruption and healthy-copy fallback, live detach/replacement, repair
  followed by another loss, retention/GC, absent-source operation, partial
  peer availability, physical headroom/reclaim, retired-volume configuration
  replay, and nonempty SQLCipher rekey for both control and parity databases.
  Docker-controller safety and real NAT-PMP lifecycle gates also passed during
  the correction series. All compilation and execution were local; no remote
  compilation server was used.

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
