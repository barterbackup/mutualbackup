# Product TODO

## Milestone 2 corrective gate — blocks Milestone 3

A fresh source-only audit of `e9fafc2..8426910` found the concrete defects
below. They describe behavior already implemented, not delayed product work.
Close each item with a focused regression, rerun the complete Milestone 2
gates, and repeat the source-only review before starting Milestone 3.

### Recovery and durable state

- Make a publisher's endpoint sequence floor recoverable from its seed and
  authenticated guild state. Today a node recovered after the 15-minute DHT
  TTL can restart at sequence one while surviving peers retain a much higher
  expired floor indefinitely, so they ignore its valid new endpoint for about
  five minutes per missing sequence. Never depend on the old live DHT record as
  the only source of this monotonic state. Regress a long-offline seed-only
  recovery at a changed address while another member retains the old floor.
- Reconcile recovered checkpoint installation as one durable transition. A
  crash after committing the checkpoint but before writing
  `user-revision-head` or clearing recovery scratch makes restart take the
  local fast path without repairing either item; a subsequent backup then
  rejects the missing head. Atomically commit the control-database pieces or
  make startup reconstruct and validate all of them. Inject interruption at
  every boundary after checkpoint publication.
- Complete a storage-only member's recovery attempt after installing its
  checkpoint. With no owned revision there is no plaintext restore and thus no
  call that clears `recovery-attempt/active`; after the member later creates its
  first revision, restore can be rejected against that stale checkpoint pin.
  Regress storage-only recovery followed by first backup and restore.
- Preserve the pinned recovery branch, not only its generation. A retry now
  accepts any higher unanimously signed checkpoint without proving that it
  descends from the checkpoint already pinned by the attempt. Require the exact
  pin until installation or validate a complete authenticated parent chain for
  advancement. Regress a higher-generation signed non-descendant fork.
- Enforce the configured parity-volume budget while importing local parity
  during cold recovery. That path currently uses an unlimited store wrapper,
  unlike ordinary parity publication, and can write past the operator's cap
  until the SQLCipher filesystem reaches ENOSPC. Reserve/account recovery
  writes identically and make insufficient capacity explicit and resumable.

### Reflink capture and anchor storage

- Drive tree enumeration from the pinned protected-root descriptor, or prove
  that the pathname-resolved walk root is the same filesystem object throughout
  capture. `WalkDir` currently reopens the pathname and skips its root entry, so
  an empty mount placed over the root in that window can commit an empty
  manifest while final validation checks only the covered original descriptor.
  Add a fault-injected root mount-swap regression.
- Add a safe abandon-and-replan transition for an uncommitted capture intent.
  A failed capture retains an exact plan and the deterministic revision ID is
  reused forever; if the user fixes the rejected tree and thereby changes root
  timestamps, every later backup fails `SourceChanged`. Clean only owned
  staging/final anchors and regress reject, repair source, then retry.
- Make first-use anchor-area creation crash-recoverable. The deterministic
  final directory is created before its marker is complete, and a crash or
  ENOSPC leaves a path that every retry treats as a permanent collision. Build
  and sync the private marked area under an owned staging name, publish it with
  a no-replace rename, and safely reconcile owned leftovers.
- Replace pathname `remove_dir_all` anchor cleanup with descriptor-relative,
  no-cross-mount deletion tied to the expected anchor-area filesystem. A bind,
  FUSE, or subvolume mount at a mutable staging/final anchor path can currently
  make cleanup descend into and delete the mounted contents.
- Reject special objects without first performing a readable open. Capture
  opens every non-directory entry with `O_RDONLY|O_NONBLOCK` before checking
  the live type, so character or block device open handlers can run even though
  the entry is then rejected. Pin and validate with a non-I/O descriptor and
  acquire a readable handle only for the verified regular inode.

### Docker lab safety

- Protect every application-managed child namespace below `LAB_ROOT`, not just
  the canonicalized root. An `images`, `mounts`, `seeds`, or `configs` symlink
  can redirect mounts and destructive `reinit` operations outside the lab; an
  owned external `nodeN.btrfs` still passes the leaf-file check. Require owned,
  non-symlink marked directories and resolve every destructive target beneath
  that verified namespace. Extend the safety test with child substitution.

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
