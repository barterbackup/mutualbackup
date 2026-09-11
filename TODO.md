# Product TODO

## Milestone 3 closeout — required before Milestone 4

- Enforce `TorMode` at the actual dial and established-session boundary, not
  only while copying addresses into application-managed caches. The composite
  swarm always installs QUIC, and Kademlia can temporarily learn and dial
  addresses directly from query responses; today a `require-tor` node can
  therefore dial and use a returned IP address. Apply the policy to every
  behaviour-originated dial and reject a forbidden inbound or outbound session
  before Identify, Kademlia, or application traffic. Gate this with a mixed DHT
  whose peer responses deliberately advertise forbidden transports.
- Make request fallback connection- and attempt-aware. Consume the exact
  `connection_id` on outbound failure, quarantine or close an unhealthy live
  session, use a healthy duplicate when one exists, and advance one tier only
  once even when libp2p reports both a dial error and a request failure. Do not
  let request-response round-robin a retry onto a stale or retiring session;
  retain the same signed, idempotent request across the sequential
  direct/hole-punch, relay, and Tor attempts. Periodic recovery probes must try
  every better available tier rather than repeatedly skipping an intermediate
  tier. Cover live-session timeouts, duplicate-session failure, and the full
  three-tier race.
- Keep connection path and session telemetry in one consistent state
  transition. Failed DCUtR currently changes `connection_paths` from `relayed`
  to `relay-fallback` without updating the corresponding active session,
  history, or opened/closed metric buckets. Assert the same exact provenance in
  peer status, active and recent sessions, path counters, and application-byte
  attribution before and after duplicate collapse.
- Strictly parse every MutualBackup onion endpoint as one canonical
  `/onion3/<v3-address>:443` transport, optionally followed by the expected
  `/p2p` identity. Validate all 35 address bytes, including the v3 checksum and
  version, as well as the fixed service port; matching only the embedded
  Ed25519 key lets unusable bootstrap and discovered endpoints pass validation.
  For anonymous inbound Tor streams, do not report the local onion listener as
  `send_back_addr`; model the unknown remote address so Identify and AutoNAT
  cannot promote or probe the server's address as the client's address.
- Make daemon and Arti shutdown explicit and awaitable. Handle both SIGINT and
  SIGTERM, cancel the background jobs, ask the P2P loop to shut down, await its
  task, stop and join Tor work, and withdraw any gateway mapping before exit.
  Carry the Arti loader's resolved `storage.state_dir` through runtime ownership
  and failed-start cleanup: an operator Arti file can override that path, while
  cleanup currently waits on the unrelated daemon-option default and can race
  the next manual unlock against the old onion-service lock. Gate clean stop,
  failed unlock, immediate unlock retry, and restart with an overridden path.
- Finish the admitted gateway-mapping path rather than treating fabricated
  external-address injection as its acceptance test. The mapping library maps
  the default-route local address, while current validation also accepts a QUIC
  socket bound only to another interface; either support and verify the exact
  selected local address or restrict this mode to a compatible wildcard/default
  route listener. Add a real isolated PCP, NAT-PMP, or UPnP fixture that proves
  acquisition, publication, replacement, loss, reacquisition, and orderly
  withdrawal. Keep the static Nix artifact as an enforced regression gate as
  dependencies change.
- Separate opportunistic addresses learned from non-guild Identify peers from
  the quota reserved for configured, guild, and recovery endpoints. Unknown
  peers currently consume the same 1,024-peer cache, so sequential ephemeral
  Peer IDs can prevent a legitimate new endpoint from being retained for the
  cache lifetime. Unknown observations must be expendable and must never block
  or evict an authorized peer's endpoint.

## Inherited contract regression found during Milestone 3 closeout

- Bring `protocol/local-control.cddl` back into exact agreement with the Rust
  `ProtectedRoot`: the implementation serializes `filesystem_id` and
  `root_inode`, while the schema still specifies the removed
  `filesystem_device`. Add byte-exact `Status` and `RootAdded` response vectors
  so another storage-identity change cannot drift silently.

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
