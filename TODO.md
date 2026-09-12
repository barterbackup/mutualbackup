# Product TODO

## Milestone 3 corrective follow-up — required before Milestone 4

- Construct the final signed local endpoint set from individually validated,
  live candidates before applying the protocol bound. The current status path
  accepts every runtime circuit listener, sorts the mixed direct, mapped,
  relay, and onion set, and truncates it to eight before validation. One relay
  reservation can expand into several listeners, so this can discard a live
  onion endpoint; one unsupported runtime listener can instead abort the whole
  DHT/peer-exchange refresh. Reject bad candidates individually and report the
  degradation, then make a deterministic transport-aware selection that
  preserves a live onion path whenever Tor is enabled. Cover a multi-address
  relay, an otherwise valid wildcard listener, and one invalid runtime
  candidate.
- Restrict operator-supplied external addresses to the concrete direct QUIC
  endpoints that option promises. The shared endpoint validator currently also
  accepts a self onion address or relay-circuit address. Those configured
  values are advertised unconditionally, so an onion survives loss of its Arti
  listener and a circuit can be published without any live reservation. Onion
  and circuit publication must come only from their active runtime listeners;
  add loss/no-reservation regressions.
- Strictly preflight every configured bootstrap address instead of merely
  parsing it and silently dropping entries forbidden by the effective Tor
  policy. Require a canonical, bounded, supported endpoint ending in its
  destination peer ID, including onion/peer identity agreement, before Arti or
  the libp2p swarm starts. Surface policy-incompatible entries and reject a
  recovery configuration that has no usable bootstrap/routing path left after
  policy selection. Cover malformed transport shapes, missing or misplaced
  peer IDs, wildcard or zero-port endpoints, and IP-only/onion-only policy
  mismatches.
- Bind an automatic gateway lease and its advertised address to the exact live
  wildcard QUIC listener whose port was mapped. The mapper currently reads that
  listener once and never observes its closure; if Tor or a relay keeps the
  swarm alive, the dead UDP port remains mapped and signed. On listener loss,
  acknowledge lease deletion and withdraw the mapped endpoint before further
  publication, then either supervise a new listener/mapping pair or expose the
  loss as a deliberate fatal/degraded transition. Regress with another ingress
  path keeping the daemon alive.
- Protect the exact connections that own circuit-relay reservations from both
  same-tier duplicate collapse and cross-tier policy retirement. The current
  equal-tier exemption covers only peers on which this node configured an
  outbound reservation; `prefer-tor` promotion can still close that backing
  QUIC connection, and relay-server reservations accepted from guild members
  have no connection-level protection at all. Track both client and server
  reservation lifecycles, release protection only after the
  reservation/listener ends, and test policy promotion on each side without
  circuit interruption.
- Re-run duplicate-session selection after a selected connection disappears.
  If two same-tier alternatives are both awaiting retirement, the close path
  clears both markers to recover availability but never designates one of them
  for retirement again, leaving redundant sessions indefinitely. Preserve one
  deterministic healthy survivor, reschedule every other eligible duplicate,
  and cover the three-connection close ordering.

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
