# Product TODO

## Milestone 3 closeout — required before Milestone 4

- Replace the peer-wide fallback counter plus unconstrained
  `request_response::send_request` dispatch with transport-attempt state that is
  bound to the connection and path actually used. Today an inbound or
  behaviour-originated lower-priority connection can carry successful traffic
  without entering `fallback_tiers`, so `prefer-tor` can remain on IP forever;
  advancing fallback uses `DisconnectedAndNotDialing`, which cannot dial the
  newly selected tier while any retained connection exists; and the retry may
  then run over a different live tier while being labelled as the selected one.
  Ensure that each sequential tier is genuinely attempted, reconcile every
  established path with policy, handle successful wrong-tier traffic, and give
  one logical request a bounded total attempt/deadline budget. Gate the direct
  → relay → onion races with simultaneous retained and closing sessions.
- Preserve an exact closed-connection path tombstone until all request-response
  terminal events for that connection have been handled. Libp2p queues its
  `OutboundFailure` while closing the connection but exposes the public
  `ConnectionClosed` first; the current handler removes `connection_paths` and
  later substitutes the current selected-address hint. That can charge failure
  to the wrong transport and advance fallback even though the selected tier was
  never tried. Test event ordering, metrics, and policy transitions rather than
  calling the handlers in an impossible order.
- Make a preferred-path upgrade tentative until replacement health is stable.
  Establishing a better path currently clears or lowers the fallback tier
  immediately. If that path dies before the retained fallback is retired, the
  fallback is correctly kept alive but its tier is never restored, so all
  preferred-path probing stops. Recompute active policy state after every
  connection transition and prove that direct/DCUtR and relay upgrades resume
  after a short-lived replacement.
- Put the complete Arti/P2P construction phase under shutdown and timeout
  supervision, not only the later readiness wait. Always drain an Arti runtime
  after a readiness-channel close even when joining the P2P task returns a
  panic, and distinguish a constructor attempt that actually launched/owns an
  onion service from an early state-lock failure so cleanup neither races a
  second unlock nor masks the original error. Add signal-during-construction,
  P2P-startup-panic, failed-manual-unlock, and state-already-in-use regressions.
- Give an acquired gateway mapping one cleanup path that runs on every exit.
  `run_port_mapping` currently deactivates and acknowledges release only on its
  explicit shutdown-watch branch; a P2P publication error or mapper-service
  termination drops the client without invalidating an active PCP/NAT-PMP/UPnP
  lease. Withdraw the libp2p address and attempt an acknowledged mapping release
  before returning the original error, including daemon-shutdown races, and
  cover those exits in the real mapper fixture.
- Validate and canonicalize the complete local advertised endpoint set before
  it is accepted for publication. Configured external onion addresses are not
  currently checked against the seed-derived identity, a configured terminal
  `/p2p` component may name another peer, and eight configured addresses plus
  the generated onion or mapped address can exceed the signed protocol limit.
  Fail invalid configuration before readiness and define deterministic bounded
  selection/replacement for runtime-generated endpoints so guild creation,
  join, DHT refresh, and peer exchange cannot enter a permanent publication
  failure loop.

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
