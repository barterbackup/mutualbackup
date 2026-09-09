# Product TODO

## Milestone 2 corrective gate — blocks Milestone 3

A source-only audit at `f339fd7` reopened the gate. The recovery-network
corrections remain sound, but the following current-path defects must be fixed
and covered by focused regressions before Tor work begins.

### Reflink capture and restore lifecycle

- Make descendant capture descriptor-bound, not merely root-bound. `WalkDir`
  opens descendant directories through paths independently of the descriptors
  later retained and validated. A transient child overmount can therefore
  supply the enumeration, disappear, and leave capture validating the unchanged
  underlying directory while committing an incomplete manifest. Enumerate,
  enforce the filesystem boundary, and validate each directory through the same
  pinned handle; regress a child overmount removed after enumeration begins.
- Make capture and cleanup resource limits real. Capture retains one descriptor
  per file and directory until final validation, so an ordinary valid tree can
  exhaust `RLIMIT_NOFILE` far below the advertised 8,192-entry catalog limit.
  Owned-tree cleanup first collects every directory name into a vector and only
  then applies its entry budget, so hostile fanout can exhaust memory before
  rejection. Use bounded descriptor consumption and streaming or bounded-batch
  directory enumeration, with low-FD-limit and excessive-fanout regressions.
- Replace `remove_dir_all` in ordinary restore and cold-recovery staging cleanup
  with the same descriptor-relative, no-cross-mount removal rule required for
  anchors. Checking only the staging root does not protect an external tree
  mounted at a descendant from deletion. Bind cleanup to the expected staging
  identity and keep failed cleanup as a visible durable obligation.
- Journal recovered re-anchoring before creating its final anchor. A crash after
  `ReflinkAnchor::capture` but before the manifest transaction currently leaves
  an unreferenced full anchor, and failure to remove the replaced anchor is
  silently forgotten. Make creation, metadata installation, and retirement a
  resumable intent whose orphan cleanup remains durable until it succeeds.

### Docker-lab ownership and crash safety

- Confine every mutable per-node leaf, not only its parent namespace. Loop-record
  redirection follows an existing symlink or hard link, while staged and final
  image checks accept hard-linked regular files; those paths can truncate,
  format, or later modify an external inode. Create records without following
  aliases and require exclusive, unmounted, lab-owned image inodes before every
  mutating operation.
- Harden teardown as strictly as creation. `unmount_filesystem` accepts an image
  symlink through `-f` and detaches every loop associated with its target without
  validating image provenance or refusing a loop still mounted elsewhere. It
  must validate the exact managed leaf and mounted-loop state before detach.
- Make namespace-marker creation recoverable. Interruption after writing its
  temporary marker but before rename leaves a nonempty unmarked root that all
  later invocations reject. Either clean up a verifiable owned temporary marker
  on retry or use an initialization protocol that cannot strand the namespace.

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
