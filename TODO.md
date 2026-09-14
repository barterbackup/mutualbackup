# Product TODO

## Milestone 4 completion blockers

Source review of `7b1114a..b8ffc90` on 2026-09-14 reopened Milestone 4.
The findings below follow source paths and durable-state transitions; no builds,
tests, or runtime probes were performed for this review. Close these blockers
and their regression gates before advancing to Milestone 5.

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
- [ ] **M4-06 / P1 — Isolate corruption from healthy copies and status.**
  Scrub marks a corrupt volume Failed but retains its store
  (`crates/mb-node/src/volume.rs:649`). Local and pooled network readers stop
  on its first integrity error (`volume.rs:446`,
  `crates/mb-node/src/node.rs:507`), so it can mask a verified replacement on a
  later volume. Status also verifies every payload and fails on the corruption
  (`volume.rs:380`). Preserve integrity errors while trying healthy copies,
  and keep failure/status reporting available. Cover corruption, scrub,
  replacement repair, local/network reads, and restart with either ordering
  of source/replacement UUIDs.
- [ ] **M4-07 / P1 — Retire network readers before declaring a disk removable.**
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
- [ ] **M4-08 / P1 — Detect loss of an established parity database.**
  `open_volume_store` verifies the manifest but opens a missing database with
  creation enabled (`crates/mb-node/src/volume.rs:921`,
  `crates/mb-store/src/database.rs:2113`). A database truncated to zero bytes is
  also initialized under the old UUID (`database.rs:1614`). Existing receipts
  survive, while the volume can appear Online with zero objects. Distinguish
  first initialization from reopening acknowledged storage and record loss
  instead of silently recreating it. Test removal and truncation of only an
  established database while retaining its manifest and control receipts;
  require explicit replacement/reconciliation and visible degradation.
- [ ] **M4-09 / P2 — Migrate repaired and emergency objects.**
  `store_repair` stores valid objects with an empty acknowledgement
  (`crates/mb-node/src/volume.rs:536`), but migration always calls
  `load_acknowledgement` (`volume.rs:720`), which rejects empty values
  (`crates/mb-store/src/database.rs:1484`). Any such object blocks completion
  of a drain. Preserve the distinct acknowledgement semantics of ordinary
  publication and repair, and cover migration of assigned repairs plus
  emergency information and parity objects.
- [ ] **M4-10 / P2 — Resume migration without reserving duplicate capacity.**
  An interruption after destination commit leaves both copies and a receipt
  naming the destination. Retry deletes that receipt
  (`crates/mb-node/src/volume.rs:729`) and demands space for another whole
  object (`volume.rs:574`) before discovering the already verified copy.
  Reuse committed destination state. Cover interruption after destination
  commit with a destination budget exactly equal to the copied payload,
  followed by reopen/reconcile and successful drain; the existing interruption
  fixture allows twice that capacity (`volume.rs:1473`).
- [ ] **M4-11 / P2 — Preserve completed drains through daemon configuration.**
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
- [ ] **M4-13 / P1 — Bound memory for storage status and migration.**
  `ready_objects` collects all full shard payloads into one vector
  (`crates/mb-store/src/database.rs:1241`). Both status and migration use it
  (`crates/mb-node/src/volume.rs:386`, `volume.rs:713`), so a routine status
  request can exhaust daemon memory when stored parity exceeds RAM. Count
  metadata without loading payloads and migrate verified objects in bounded
  batches. Verify memory bounds independently of total stored volume size.
- [ ] **M4-14 / P2 — Implement physical-space accounting and reclamation.**
  The volume requirements in `plan.md` distinguish logical quota from physical
  allocation and require reclaim plus operational headroom. Current accounting
  only sums payload lengths (`crates/mb-store/src/database.rs:1231`), placement
  subtracts logical headroom (`crates/mb-node/src/volume.rs:567`), and collection
  only deletes rows (`database.rs:1348`). There is no implemented physical-space
  accounting or database reclaim operation. Track allocated database/WAL space
  and available filesystem space, preserve recovery/GC headroom, and provide
  controlled reclaim. Cover deletion/reclaim and a nearly full filesystem
  independently of the configured logical quota.

- [ ] **Re-run the Milestone 4 closure gate after corrections.** Add the
  regressions above, including interruptions between control/capture/repair
  records rather than only the volume helper transitions. Run the required
  gates locally, including the disposable-Btrfs/reflink and generation-2
  seed-recovery paths, corruption, live volume detach/replacement, repair
  followed by a second loss, safe retention/GC, absent-source operation, and
  partial DHT/network failure. The ignored
  `repeated_multi_owner_backups_commit_over_quic` already asserts generation-2
  recovery (`crates/mb-node/src/network/p2p.rs:11834`); its earlier Milestone 3
  result cannot validate the newly changed recovery/GC path. Do not reuse that
  result to mark Milestone 4 passed. Runtime validation belongs to the subsequent
  correction gate.

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
