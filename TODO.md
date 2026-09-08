# Product TODO

## Milestone 2 corrective follow-up

The latest source-only closure review found the current defects below. They are
mistakes in implemented behavior or its regression gate, not deferred product
features. Fix and remove them before beginning Milestone 3.

- Preflight the seed and identity-manifest pair before installing a missing seed
  output. `init --seed-file` currently writes a new seed and only afterwards
  discovers that an existing `identity.toml` belongs to another identity. The
  rejected command therefore mutates disk and leaves a seed that makes every
  retry fail. Preserve valid seed-first interruption recovery, but cover absent
  seed plus matching and conflicting manifests for generated and supplied
  recovery strings.
- Return a manually unlocked daemon to `Locked` when asynchronous libp2p startup
  fails. Synchronous runtime-construction errors already retry, but listener or
  relay failure and the startup timeout respond to the CLI and then terminate
  `mutualbackupd`. Tear down the failed node/network attempt while retaining the
  data-directory lock and control listener, and prove that status plus a later
  unlock still work. Auto-unlock may continue to fail the process.
- Make cold recovery accumulate its durable progress. Verified recovered shards
  are written to `recovery_shards`, but every later recovery attempt downloads
  all preceding coding groups again. Validate and reuse matching staged shards
  so disjoint peer-availability windows and daemon restarts can converge; reject
  conflicting staged state and add an alternating-availability regression.
- Allow the durable recovery-restore state machine to handle its own target.
  `recover_from_dht` currently rejects any existing target before
  `restore_recovered_revision` can verify the native ID and ownership marker of
  a target published by the same job. Remove that contradictory outer check,
  retain rejection of foreign targets, and inject interruption after the atomic
  publish and during finalization.
- Separate truly persistent operator addresses from bounded, replaceable network
  hints. Recovery candidates and changing guild endpoints currently pass through
  `AddAddress`, which permanently accumulates peers and addresses without an
  aggregate cap—even before recovery authority is established—and also exempts
  their telemetry from eviction. Give attempt-scoped and signed endpoints an
  expiring/replacement lifecycle, promote only validated bounded state, and
  cover repeated churn and hostile recovery candidates.
- Make Docker-lab filesystem provisioning interruption-safe and enforce mount
  provenance on every node start. Image existence currently stands in for
  completed `mkfs.btrfs`, so interruption after `truncate` leaves an image that
  no later `up` can repair. In addition, `start` and `restart` bypass the exact
  image/loop/mount check used by `up` and `down`. Record or atomically publish
  completed lab-owned images, reject ambiguous existing files, and test partial
  creation, missing mounts, and foreign mounts.
- Make Docker `reinit` one durable, resumable transaction through successful
  recovery. Its intent is removed immediately after `recover-init`, before the
  recovery config, container, guild recovery, and restore; a later `up` then
  overwrites the config and follows normal guild setup. Durably persist the
  stage, bootstrap choice, and restore target—including containing-directory
  sync—before erasing the image; keep them until success; and make
  `up`/`reinit` resume each boundary. Before wiping, require at least three
  responsive members of the same active guild, not merely three daemons that
  answer `status`.

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
