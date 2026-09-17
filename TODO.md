# Product TODO

## Milestone 4 follow-up source review — closed 2026-09-15

Source review of `197c6b0..1b9f99e` found one remaining completion blocker
in M4-37's capacity correction. Per-holder serialization removes the explicit
probe burst, but receiving a response does not guarantee that the holder has
released its request worker. No remaining blocker was identified in M4-38's
matching READY publication retry correction. That review reopened Milestone 4;
the earlier passing gates remained evidence for their exercised cases. The
review ran no builds, tests, or runtime probes. Commit `193f67e` resolves
M4-39, and the local correction gate below passed.

- [x] **M4-39 / P2 — Release holder capacity before exposing a completed response.**
  The blocking worker retains its inbound permit while enqueueing
  `InboundResult` (`crates/mb-node/src/network/p2p.rs:4432`, `p2p.rs:4434`).
  The event loop can send that response before the worker resumes and drops
  the permit (`p2p.rs:2844`, `p2p.rs:2852`). Consequently, even the new
  sequential discovery loop (`p2p.rs:6206`) can receive retryable Busy for its
  next probe when the holder has one available worker (`p2p.rs:4394`). With
  A/B/C holding assigned indices 0/1/2, D/E offline, and emergency indices 3
  on B and 4 on C, pause B's worker after enqueueing the absent-index-2
  response. B's next probe for its existing index 3 is rejected while that
  worker still owns the permit. Inventory discards the error without retry
  (`p2p.rs:6223`); even if it discovers C's index 4, the known layout loses
  indices 2 and 4 together with C and persists Emergency instead of the
  actual Degraded status (`p2p.rs:6365`, `p2p.rs:6379`). Release or transfer
  permit ownership so capacity is available before the response becomes
  observable, preserving bounded response handling, or handle retryable
  capacity outcomes with a bounded policy before finalizing inventory. Add
  a deterministic regression that holds the preceding worker after its
  result is queued, then exercises the next sequential probe with one
  available worker and verifies complete discovery and durable Degraded
  status after a read-only audit and reopen. The constrained-permit regression
  at review time (`p2p.rs:11767`) did not force this response/permit handoff.
- [x] **Run the Milestone 4 correction gate after M4-39.**
  On 2026-09-15, commit `193f67e` passed formatting, locked all-target
  workspace tests, warning-free locked all-target workspace Clippy, and Docker
  controller safety. A freshly provisioned disposable 2 GiB Btrfs filesystem
  with `user_subvol_rm_allowed` passed the complete
  `scripts/reflink-acceptance.sh` gate, including capture and recovery
  reconciliation, shared-filesystem WAL headroom, repeated multi-owner QUIC
  backup, five-daemon seed/DHT recovery after source and holder loss, and
  isolated direct/DCUtR/relay paths. The deterministic handoff regression
  leaves one request permit available on each reachable remote holder, holds
  the first completed workers after their results are queued, and verifies
  complete discovery with durable Degraded status through reopen. All
  compilation and execution were local; no remote compilation server was used.

## Milestone 4 follow-up correction record — M4-37 and M4-38

Source review of `fb73787..546a1b9` found two completion blockers in the
latest audit and physical-admission changes. The retired-volume correction
has no remaining blocker identified in this review. Commits `736bf20` and
`fea97b1` were recorded as resolving the two findings, and the local correction
gate below passed. The later source review recorded M4-39 for the remaining
response/permit handoff; commit `193f67e` and the gate above close it. The
review itself ran no builds, tests, or runtime probes.

- [x] **M4-37 / P2 — Avoid overloading holders during emergency-copy discovery.**
  The new emergency inventory launches four probes per remote holder together
  (`crates/mb-node/src/network/p2p.rs:6193`, `p2p.rs:6212`). A supported holder
  with `max_connections = 1` immediately rejects overlapping requests with
  retryable `Busy` (`p2p.rs:4394`; existing worker-limit test at `p2p.rs:11013`).
  Audit treats those responses as missing copies without retrying
  (`p2p.rs:6214`, `p2p.rs:7415`). With D/E offline, A/B/C holding assigned
  indices 0/1/2, and emergency indices 3 on B and 4 on C, the actual layout
  survives another holder loss. If absent-index probes occupy B/C's workers
  when their emergency-copy probes arrive, the audit discovers only three
  indices and persists Emergency instead of Degraded (`p2p.rs:6349`,
  `p2p.rs:6369`). Serialize discovery per holder or handle retryable capacity
  responses with bounded retries before finalizing inventory. Add a regression
  with low-capacity holders and overlapping probes, checking complete location
  discovery and correct durable status after a read-only audit and reopen.
- [x] **M4-38 / P2 — Allow matching READY publication retries near capacity.**
  The receipt branch now requires physical space for another complete sector
  plus WAL backfill before validating the existing object
  (`crates/mb-node/src/volume.rs:711`). Matching READY bytes and acknowledgement
  already complete without a parity write in
  `crates/mb-store/src/database.rs:1505`. A publish interrupted after durable
  object/receipt publication but before its peer-operation result commits is
  reexecuted on retry (`crates/mb-node/src/network.rs:695`, `network.rs:708`).
  If remaining space above headroom is below the new-sector reservation, the
  retry now returns CapacityExceeded even though the sector is already stored
  and enough space remains for its small control completion records. Validate
  the exact existing payload, metadata, and acknowledgement before treating a
  retry as requiring growth; retain admission for actual writes and reject
  conflicting retries. Cover interruption, reopen, and retry at the physical
  boundary through the peer publication path, including durable completion
  and unchanged parity allocation. The current boundary regression
  (`volume.rs:2479`) only exercises admission of a new object.
- [x] **Run the Milestone 4 correction gate after M4-37 and M4-38.**
  On 2026-09-15, the corrected source tree passed formatting, locked all-target
  workspace tests, warning-free locked all-target workspace Clippy, and Docker
  controller safety. A locally provisioned disposable 2 GiB Btrfs filesystem
  passed the complete `scripts/reflink-acceptance.sh` gate, including capture
  and recovery reconciliation, shared-filesystem WAL headroom, repeated
  multi-owner QUIC backup, five-daemon seed/DHT recovery after source and
  holder loss, and isolated direct/DCUtR/relay paths. Focused regressions cover
  one available request worker per remote audit holder, complete location
  discovery with durable Degraded status, and interrupted READY publication
  replay at constrained headroom without parity growth. All compilation and
  execution were local; no remote compilation server was used.

## Milestone 4 follow-up correction record — M4-34 through M4-36

Source review of `668324f..d12f5fb` found three remaining completion blockers
in the corrections to M4-29, M4-32, and M4-33. Commits `9081266`, `7c58281`,
and `89c6569` were recorded as resolving them, and the local correction gate
below passed. The latest source review above reopens milestone completion.
Earlier passing gates cover their exercised cases, but not the schedules
below. This review ran no builds, tests, or runtime probes.

- [x] **M4-34 / P2 — Reserve WAL backlog even when automatic checkpointing stalls.**
  Setting `wal_autocheckpoint = 1` (`crates/mb-store/src/database.rs:2266`)
  requests a PASSIVE checkpoint; it does not guarantee that backfill completes.
  The pinned SQLCipher source caps backfill at active readers and its automatic
  hook ignores checkpoint errors. Peer reads use connections independent of
  the writer lock (`crates/mb-node/src/network.rs:617`,
  `crates/mb-node/src/node.rs:505`). A held read snapshot can therefore leave
  MiBs of new pages in WAL across many writes. After it finishes, the next
  ordinary write can pass admission with free space equal to headroom plus
  400 KiB, then checkpoint those MiBs into the main database. Admission still
  reserves only the current object and fixed overhead
  (`crates/mb-node/src/volume.rs:710`,
  `volume.rs:1343`). Reopening a large WAL left by an interrupted previous
  version also does not flush it merely by changing the threshold. Reserve
  outstanding main-file growth or coordinate readers and verify checkpoint
  completion before relying on a bounded reserve. Cover held readers and
  upgrade with an uncheckpointed WAL at the physical headroom boundary,
  including control storage on the shared filesystem. The new database test
  (`database.rs:3516`) uses fresh stores with one connection per database.
- [x] **M4-35 / P2 — Settle pending intents and stale receipts before empty drain retirement.**
  `settle_empty_volume_cleanup` clears only `volume-copy-cleanup`
  (`crates/mb-node/src/volume.rs:1067`). An emergency repair interrupted at
  `WriteIntentStored` leaves a durable marker and intent without a payload
  (`crates/mb-node/src/node.rs:2465`, `volume.rs:764`). Startup preserves the
  intent when the object is absent (`volume.rs:795`). Draining this empty
  volume then marks it Retired and closes its store (`volume.rs:952`). Later
  emergency cleanup/GC requires the intent's volume, cannot access the closed
  store, and never retires the marker/proof or intent (`volume.rs:616`,
  `node.rs:2505`). A receipt left by interruption after `GarbageObjectRemoved`
  has the analogous problem. Reconcile all durable location evidence against
  the verified-empty source before declaring it removable, preserving valid
  destination receipts. Also handle cleanup obligations already attached to
  Retired volumes by the previous implementation. Extend the emergency
  interruption regression (`node.rs:5818`) through reopen, drain, cleanup,
  disk removal, and repeated reopen; cover interrupted GC followed by drain
  and assert that intents, receipts, markers/proofs, cleanup records, and
  garbage candidates converge.
- [x] **M4-36 / P2 — Report protection from all verified emergency-copy locations.**
  Discovery stops at the first valid alternate for each missing shard
  (`crates/mb-node/src/network/p2p.rs:6197`), but repair can create another
  copy even when it already found one (`p2p.rs:6265`). With D/E absent and
  surviving node IDs A < B < C holding indices 0/1/2, the first repair stores
  3 on A and 4 on B. The second stores another 3 on C and another 4 on A.
  The resulting layout survives any further single host loss, yet a later
  audit with repair disabled finds both emergency indices first on A and
  ignores their other copies. Its incomplete location sets report that losing
  A leaves only two indices and persist Emergency instead of Degraded
  (`p2p.rs:6318`, `p2p.rs:6338`). Collect all verified locations, or an
  equivalent complete inventory, for placement and durable protection status.
  Cover repeated repairs followed by read-only audits and reopen, as well as
  corrected older concentrated layouts. The new outage regression
  (`p2p.rs:11702`) reconstructs from all copies collected directly from nodes;
  it does not check that a later audit discovers the same protection.

- [x] **Run the Milestone 4 correction gate after M4-34 through M4-36.**
  On 2026-09-15, the exact corrected source tree passed formatting, locked
  all-target workspace tests, warning-free locked all-target workspace Clippy,
  and Docker-controller safety. A locally provisioned disposable 2 GiB Btrfs
  filesystem passed the complete `scripts/reflink-acceptance.sh` gate. That
  gate included the held-reader parity/control WAL headroom boundary, capture
  and recovery reconciliation, repeated multi-owner QUIC backup, five-daemon
  seed/DHT recovery after source and holder loss, and isolated direct/DCUtR/
  relay network paths. Focused regressions also cover an old-threshold WAL
  reopen, pending intent and stale receipt retirement, already-Retired cleanup,
  repeated emergency repairs, complete copy discovery, durable audit status,
  and reconstruction after every surviving-host loss. All compilation and
  execution were local; no remote compilation server was used.

## Milestone 4 correction review — prior correction record

Source review of `8411f7d..2da3e82` found the blockers below in the correction
and its Milestone 4 integration. M4-29 also checks the existing emergency
placement against the milestone's outage-layout requirement. Earlier passing
gates remain historical evidence for their exercised cases; they do not close
these failure schedules. This review ran no builds, tests, or runtime probes.
Commits `27cb1b2`, `a265cc1`, and `04875a9` were recorded as resolving M4-28
through M4-33, and the local correction gate below passed. The follow-up above
supersedes that closure for the remaining M4-29, M4-32, and M4-33 schedules;
the checked entries below preserve the prior correction record.

- [x] **M4-28 / P1 — Resume legacy parity rekey after manifest publication.**
  The new manifest-present initialization branch opens only with the wrapped
  random key (`crates/mb-node/src/volume.rs:1124`). Legacy migration publishes
  that manifest before rekeying the existing database (`volume.rs:1151`,
  `volume.rs:1171`), and the control registry is saved only after initialization
  returns (`volume.rs:192`). An interruption between manifest publication and
  rekey leaves a valid old-key database and no registry. Restart now fails in
  initialization before reaching the legacy-key fallback at `volume.rs:1211`,
  preventing node startup (`crates/mb-node/src/node.rs:596`). Preserve recovery
  through both authenticated key states without recreating lost established
  databases. Cover a nonempty legacy database, interruption before/after rekey
  and registry publication, and successful reopen with unchanged objects.
- [x] **M4-29 / P1 — Place emergency copies across surviving failure domains.**
  Each missing shard starts with the same sorted alternate roster and stops
  at the first successful store (`crates/mb-node/src/network/p2p.rs:6254`,
  `p2p.rs:6292`). With holders D/E unavailable and A/B/C holding indices 0/1/2,
  both reconstructed indices 3/4 can land on lowest-ID A. The audit then
  reports Degraded by counting distinct shard indices (`p2p.rs:6308`), but
  losing A leaves only indices 1/2. Distributing the two copies across A/B
  would preserve three after any further single surviving-host loss. Track
  actual copy locations and failure domains during placement and protection
  reporting, consistent with the fixed-profile outage requirement. Cover two
  absent holders, emergency repair, loss of each surviving host in turn, and
  actual reconstruction; deleting only individual sectors while the emergency
  holder stays online (`p2p.rs:11536`) does not exercise this case.
- [x] **M4-30 / P2 — Include pending write destinations in garbage collection.**
  `remove_unreachable` checks receipts, copy-cleanup obligations, and Draining
  state, but ignores `volume-write-intent` (`crates/mb-node/src/volume.rs:595`).
  Emergency repair can commit its marker and payload, then stop before receipt
  publication (`volume.rs:747`). If that volume is absent after restart,
  reconciliation preserves its intent, but healthy-group cleanup reports
  success and deletes the marker/proof (`crates/mb-node/src/node.rs:2513`).
  On volume return, reconciliation recreates the receipt (`volume.rs:781`),
  leaving information-shard bytes without emergency classification or future
  volume GC. Include pending destinations in cleanup obligations, and retire
  their intents only when collection converges. Cover payload-before-receipt
  interruption, absent volume, cleanup, return, and repeated reopen.
- [x] **M4-31 / P2 — Preserve the old destination before replacing a write intent.**
  Publication overwrites the single object-keyed intent without retaining its
  previous destination (`crates/mb-node/src/volume.rs:729`). `store_repair`
  records an old cleanup volume only when a receipt exists (`volume.rs:651`).
  If A commits a payload but loses power before its receipt, retry with A absent
  can publish on B and replace/delete A's only location evidence. Later GC
  collects B and forgets A's copy permanently; fixing M4-30 alone cannot recover
  a discarded UUID. Preserve prior pending destinations before retargeting a
  repair or migration write. Cover an interrupted destination commit, retry on
  another volume, GC while the first is absent, and its return.
- [x] **M4-32 / P2 — Settle source cleanup obligations before drain retirement.**
  Migration deletes the source object before clearing its cleanup obligation
  (`crates/mb-node/src/volume.rs:914`). A crash at `MigrationSourceRemoved`
  leaves the obligation durable. Resume sees an empty source and retires it
  without clearing that record (`volume.rs:868`, `volume.rs:925`). Later GC
  waits permanently for the retired volume, whose store stays closed, even
  though its empty database is still attached (`volume.rs:603`). Reconcile
  outstanding obligations against the verified-empty source before declaring
  it removable. Extend transition coverage through retention/GC and reopen,
  asserting that receipts, cleanup obligations, and garbage candidates retire;
  the existing test only checks the retained payload and Retired state.
- [x] **M4-33 / P2 — Reserve accumulated WAL checkpoint growth.**
  `physical_write_reservation` budgets only the current row plus fixed overhead
  (`crates/mb-node/src/volume.rs:1299`), while SQLCipher checkpoints after
  1,000 WAL frames (`crates/mb-store/src/database.rs:2266`). Repeated inserts
  can accumulate several MiB of new pages in WAL before a threshold-crossing
  commit copies them into the main database. That write can pass admission
  with free space equal to headroom plus 400 KiB (`volume.rs:713`) and then
  consume MiBs of the reserve. The pinned SQLCipher source confirms that the
  automatic checkpoint copies all unbackfilled pages. Account for outstanding
  main-file growth or bound it with an appropriate checkpoint/reservation
  policy, including control writes on a shared filesystem. Cover many inserts
  across checkpoint thresholds at the headroom boundary; the one-object test
  at `volume.rs:2322` does not reach that boundary.

- [x] **Run the Milestone 4 correction gate after M4-28 through M4-33.**
  On 2026-09-15, the exact corrected source tree passed formatting, locked
  all-target workspace tests, and warning-free locked all-target workspace
  Clippy. A locally provisioned disposable 2 GiB Btrfs filesystem passed the
  complete `scripts/reflink-acceptance.sh` gate, including the strengthened
  shared-filesystem checkpoint/headroom boundary, generation-2 seed recovery,
  repeated multi-owner QUIC backup, five-daemon seed/DHT recovery after source
  and holder loss, and isolated direct/DCUtR/relay network paths. The new
  two-holder outage regression reconstructs after loss of each remaining host.
  Docker-controller safety checks also passed. All compilation and execution
  were local; no remote compilation server was used.

## Milestone 4 follow-up source review — prior correction record

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
implementation; Milestone 4 was reopened until they were resolved.

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

## Milestone 5 guild geometry and coding protocol (reopened)

The first closure record at `8135e0b` was premature. A follow-up source audit
found the remaining production gaps below. Commit `eeffd45` makes removal or
relabel exclude old placement from new coverage, invalidates stale audit state,
queues replacement coding without duplicating durable retries, and preserves
old layout readability. Its complete node library suite and warning-free core/
node Clippy gate passed locally. No remote compilation server was used.

- [x] **M5-01 / P1 — Protect multiple named roots with independent revision chains.**
  Signed revision format 3 and checkpoint format 6 or later bind every revision and
  retention tombstone to a protected-root UUID. The node keeps durable heads,
  dirty state, watcher signals, automatic scheduling, status, explicit backup
  selection, snapshot selection, and retention per root. Recovery atomically
  installs all certified root heads, registers the restored root under its
  signed ID, and continues that chain after restart. Focused model, retention,
  recovery-store, local-control, and restart regressions pass; the ignored
  provisioned Btrfs/QUIC gate now covers two roots for one owner and exact-root
  restore.
- [x] **M5-02 / P1 — Integrate stable-slot incremental packing into production.**
  Checkpoint format 7 authenticates the incremental `PackedCatalog`, including
  each packed sector's flat root and Merkle commitment. Backup packs all
  retained signed sectors into stable 16 KiB slots, persists the resulting
  64 KiB sectors, and codes their catalog IDs through the variable protocol.
  Coverage, lifecycle replacement, delayed GC, seed recovery, normal repair,
  and restore all resolve signed revision sectors through that catalog.
  Repacking can reuse a prior locally stored or reconstructed packed copy when
  an original owner is offline. Core partial-unpack and layout regressions plus
  node persistence/reopen coverage pass; the production Btrfs/QUIC gate checks
  stable slot positions across updates from two owners and two roots.
- [x] **M5-03 / P2 — Rank a delegated coder by every bulk lane path.**
  Peer protocol 2 adds fresh, signed, request-bound path observations over a
  canonical list of at most 256 active guild members. Each candidate reports
  its live or selected direct, relay, or Tor path to every real information
  source and parity destination. Initial attempts and retries rank the sum of
  those bulk edges, omit the candidate's own transfer when it participates,
  prefer a participant when totals tie, and retain relay/Tor as higher-cost
  available paths. The separate verifier still uses ordinary reachability and
  does not need a complete bulk-path report. Schema, snapshot, ranking, node
  library, and warning-free all-target node Clippy checks pass locally.
- [x] **M5-04 / P1 — Authorize delegated coders to fetch their signed inputs.**
  The first corrected production-gate run found that an ephemeral coding
  coordinator could stage parity but `GetCodingInformationRange` still fell
  through to the static guild-coordinator check. The first cross-user backup
  therefore accumulated retries whenever ranking selected another member.
  Treat the plan-scoped range request like the other delegated coder operations:
  only the signed plan's coding coordinator may issue it, and that caller must
  still be an active guild member.
- [x] **M5-05 / P1 — Preserve room for incremental cross-user packing.**
  The next production-gate run completed all four checkpoints but found that
  the first owner had filled every slot in its sectors. Stable positions then
  forced a later owner into separate sectors, so the authenticated catalog was
  multi-owner without any cross-user sector. New allocation keeps one vacancy
  in a single-owner sector, fills vacancies from other owners before extending
  a same-owner sector, and packs mixed sectors densely. A regression adds a
  later owner without moving any prior source chunk and requires a mixed sector.
- [x] **M5-06 / P1 — Exercise recovery-key registration in the production path.**
  The next gate passed the corrected catalog invariant and both local restores,
  then found that its manually assembled runtime had started delegated coding
  but omitted the daemon's peer-exchange worker. Format-7 DHT publication
  correctly waits for a current recovery-key epoch for every active subject, so
  all six publication passes returned without publishing. Run the real
  peer-exchange worker for every test node and wait for the certified recovery
  epochs before starting production backups.
- [x] **M5-07 / P1 — Fence coding-group lifecycle during checkpoint construction.**
  Running the production peer-exchange worker exposed that lifecycle
  reconciliation compared newly activated groups only with the still-current
  checkpoint. It retired every group created for the running backup draft, so
  that draft could never reach coverage. Treat a durable `Running` backup job
  as a checkpoint-construction fence: recovery-key and endpoint exchange still
  proceed, while group retirement waits until the job commits or is deferred.
  The production test now claims each backup job before constructing it, as the
  daemon coordinator does.
- [x] **M5-08 / P1 — Exercise the daemon's renewable DHT publication loop.**
  The next production run completed all four checkpoints, verified the packed
  catalog and local restores, then found zero recovery-readiness publishers on
  every node. Each node had built four current bundles, but the test cold-started
  provider announcements only after the 43-minute workload and allowed roughly
  three seconds for Kademlia convergence. Run the daemon's real five-second DHT
  publication/readiness worker on every node throughout the production test,
  then wait under a 60-second deadline for all subjects to certify three current
  publishers for the final checkpoint.
- [x] **M5-09 / P1 — Accept current recovery-key bundles for later dynamic checkpoints.**
  With real DHT workers running throughout checkpoints 1 and 2, every readiness
  pass still retained zero publishers. Replaying each publisher's exact stored
  bundle through the production validator found that publication correctly made
  format-2 epoch envelopes for checkpoint 7, but validation admitted them only
  for checkpoint 4. Apply the dynamic recovery-key rule to every currently
  supported dynamic checkpoint format, 4 through 7, and regress that range.
- [x] **M5-10 / P1 — Accept current recovery-key epochs during cold recovery.**
  The corrected production run completed all four checkpoints, current DHT
  readiness, packed-catalog checks, and local restores, then timed out starting
  large recovery with three live holders. Bundle admission accepted checkpoint
  formats 4 through 7, but recovery-head certification independently admitted
  current-epoch bundles only for format 4. Apply the same dynamic checkpoint
  range during certification and regress every supported version.
- [x] **M5-11 / P1 — Establish watcher coverage before backup capture.**
  The next production run again completed all coding transcripts, then found
  node 2 dirty before the deliberate post-restore source edit. Its durable
  record showed that capture saved dirty generation 1 while the asynchronously
  started watcher later wrote generation 2 for startup reconciliation. Install
  every filesystem watch before advancing that generation, expose a readiness
  signal, and require the production path to observe it before capture.
- [x] **M5-12 / P1 — Pin cold recovery against its certified dynamic state.**
  The next production run completed all 51 coding transcripts and entered cold
  recovery, then rejected a current-epoch recovery bundle because recovery
  attempt pinning ran before dynamic guild adoption and re-read the necessarily
  absent local dynamic state. Pass the already certified downloaded state into
  recovery-observation reconciliation while retaining local-state validation
  for ordinary readiness, and regress pinning on a fresh node with no installed
  dynamic state.
- [x] **M5-13 / P1 — Fetch cold-recovery coding evidence concurrently.**
  The corrected run passed M5-12, installed the recovered dynamic guild and all
  51 coding transcripts, then exhausted the 60-second recovery bound before
  staging its first assigned shard. Recovery-head validation fetched every
  transcript serially from each candidate, consuming the window before shard
  reconstruction began. Fetch transcript evidence with bounded concurrency,
  leaving the existing outbound semaphore as the global network limit, and
  regress that the collector is concurrent without exceeding its bound.
- [x] **M5-14 / P1 — Fetch coding evidence from one certified publisher at a time.**
  The next run again completed all four checkpoints and 51 transcripts, but the
  fresh node timed out before adopting guild state. Recovery-head validation
  started an eight-request transcript fetch for every candidate concurrently,
  exactly filling the test's global eight-request limit. Requests to the two
  stopped publishers could therefore hold every permit for a full protocol
  timeout while live publishers redundantly fetched the same 51 transcripts.
  Validate candidate genesis, checkpoint, and event history first, then fetch
  transcript evidence only from a publisher whose state has enough independent
  current locators. If that publisher cannot serve the evidence, continue with
  another certified candidate rather than starting duplicate bulk fetches.
- [x] **M5-15 / P1 — Stop retrying known-missing holders during variable recovery.**
  The next run completed all four checkpoints, certified one recovery head,
  installed the full event history and 50 retained transcripts, then timed out
  after activating only two of 21 locally assigned variable shards. The
  variable recovery scheduler always issued `needed + 1` requests. It let the
  fresh node's known-missing local assignment occupy the initial spare, then
  continued including a known-offline holder even after exactly `k` healthy
  remote holders had been learned. Each abandoned request retained a global
  outbound permit until its terminal event. Mark the absent local assignment
  deferred before fetching, use all remote candidates for the first probe, and
  once `k` preferred holders remain issue only those `k`, matching the bounded
  legacy recovery schedule. A focused regression pins both selections.
- [ ] **M5-16 / gate — Run the corrected production gate.**
  The ignored repeated multi-owner QUIC test had a stale checkpoint-version
  assertion, now corrected to version 7. Successive reruns exposed M5-04,
  M5-05, M5-06 after the catalog and local restore assertions passed, and M5-07
  when the daemon peer-exchange task first ran beside backup. The next run
  completed checkpoint 4 and exposed M5-08 at DHT readiness. Running the real
  publication loop throughout the next gate exposed M5-09 in bundle validation.
  The following run passed final-checkpoint readiness but exposed M5-10 when
  cold recovery applied an older, narrower copy of the same validation rule.
  The next run exposed M5-11 when its fixed watcher-startup sleep lost a race
  with capture after the full coding workload completed. The following run
  completed all 51 transcripts and exposed M5-12 when cold-recovery pinning
  consulted local dynamic state before the certified downloaded state had been
  adopted. The next run passed that transition and installed all recovered guild
  history and transcripts, then exposed M5-13 because serial transcript fetches
  consumed the recovery deadline before any shard was staged. The following run
  completed the same production workload but exposed M5-14: parallelizing each
  candidate's transcript list allowed redundant and offline candidate fetches
  to consume the complete global outbound budget before any certified state was
  adopted. The next run passed head certification and exposed M5-15 after two
  variable groups: unlike legacy recovery, variable recovery kept issuing a
  request to a deferred holder even when exactly `k` preferred holders remained,
  so abandoned requests again consumed the global budget.
  The provisioned Btrfs production path has therefore not yet passed for the
  reopened work. Run formatting, locked all-target workspace tests,
  warning-free locked all-target Clippy, and the local reflink/network
  acceptance gate after M5-01 through M5-15 close.

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
