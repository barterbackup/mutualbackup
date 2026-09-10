# Product TODO

## Milestone 2 corrective gate — blocks Milestone 3

A fresh source-only audit at `3d85e75` reopened the gate. The recent capture,
restore, and Docker-lab corrections remain useful, but the following defects
are reachable on current paths and must be fixed with focused fault regressions
before Tor work begins.

### Capture and restore ownership/durability

- Bind an anchor transaction to one validated area descriptor and one newly
  created staging descriptor. `capture_plan` currently validates the area by
  pathname, then independently uses pathnames for staging cleanup/creation,
  captured destinations, publication, and final sync. A same-UID
  rename/replacement can split those phases across different directories,
  redirect output outside the validated area, or make a committed rename
  non-durable. Anchor retirement has the same final gap: stable and legacy
  removal drop the descriptor used for unlinking and reopen the path to sync.
  Perform creation, writes, rename/unlink, cleanup, and `sync_all` relative to
  the pinned descriptors; regress area replacement before writes and between
  mutation and sync.
- Make the version-6 recovery initializer owned before it can exist. Its random
  directory is currently created before its marker, while both resume and
  cleanup ignore an initializer whose marker is absent or incomplete. A crash
  or marker-write failure therefore leaves an unowned orphan that cannot be
  reclaimed safely. Journal the exact initializer name/identity first, or use
  an equivalently atomic ownership protocol, and regress every
  create/write/rename boundary.
- Keep the first durable recovery-staging identity immutable and build through
  pinned descriptors. The current path samples an identity after verification,
  ignores a missing-marker result, lets `build_revision_restore` sample the
  pathname again, and finally overwrites the journaled identity. A replacement
  can therefore be adopted and later recursively deleted; path-based
  descendant creation can also follow a substituted intermediate symlink.
  Never adopt a later inode, and create, link, metadata-update, sync, publish,
  and clean the restored hierarchy descriptor-relatively without crossing a
  mount or symlink. Regress root and descendant replacement with foreign
  sentinels.
- Turn ordinary restore into a durable staged/publication job instead of an
  unrecorded UUID directory. A crash before rename currently strands its hidden
  tree, while a crash after rename leaves an ambiguous target that retry
  rejects. A successful rename followed by parent-`fsync` failure is likewise
  reported as failed publication and cleans only the now-missing staging name.
  Renaming/replacing the parent can also make cleanup inspect a different
  directory and mistake the absent old name for completed cleanup. Pin the
  containing directory during an attempt, distinguish pre-rename from
  post-rename failure, and retain a restart-visible obligation until either
  the expected target is durably published or the expected staging tree is
  durably removed. Regress parent rename/replacement, interruption on both
  sides of rename, and directory-sync failure.

### Docker-lab ownership validation

- Make namespace enumeration fail closed. `directory_is_empty` decides from
  `find` output but discards its failure status, and marker recovery loses the
  same status through process substitution. An owned nonempty root without read
  permission can consequently look empty, be marked as lab-owned, and later be
  chmodded and used by destructive lifecycle operations. Capture and check the
  enumerator status before adopting or cleaning a namespace; regress an
  unreadable nonempty root and a failed marker scan.
- Parse loop records as exactly one newline-terminated `/dev/loopN` token.
  Counting newlines currently accepts a valid first line followed by an
  unterminated trailing line. Detach no longer trusts the record, so this is not
  independently a Milestone 3 blocker, but it is definite malformed-state
  acceptance in the Milestone 2 lab path and should be fixed in this slice.

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
