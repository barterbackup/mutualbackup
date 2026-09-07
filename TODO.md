# Source-review TODO

These are high-confidence defects in the implemented Milestone 1 slice. They
are not a list of deferred product features.

## Urgent before Milestone 2

- Enforce the peer frame limit in the actual libp2p CBOR codec. The production
  behaviour uses the dependency defaults (1 MiB requests and 10 MiB responses),
  while the normative protocol and tests claim a 600 KiB application limit.
  Configure both codec bounds explicitly and test rejection on the real path.
- Make the learned endpoint cache replaceable, expiring, and bounded. Each DHT
  refresh currently appends the selected signed addresses to both the swarm and
  Kademlia, but never removes addresses from superseded or expired records; a
  long-lived peer can therefore accumulate stale dial targets without limit.
- Re-arm filesystem watching after a protected root is removed and recreated.
  The callback collapses every event and watcher error to the same dirty hint,
  while `watch_once` has no root-health check that ends the stale watch. After a
  successful reconciliation clears `dirty`, later edits to the replacement
  directory can be missed.
- Remove the blocking `Node` mutex acquisition from relay admission. The relay
  rate-limiter callback runs synchronously while the swarm is being polled, but
  it calls `node.lock()`; source capture and database operations can hold that
  mutex on a blocking worker, pausing all peer networking and relay decisions.

## Correctness and acceptance follow-ups

- Make application byte counters report completed I/O, or rename them to state
  that they count attempts. Outbound requests and responses are added before
  `send_request`/`send_response` succeeds, so a failed or disconnected send is
  currently reported as transferred data.
- Correct the signed-record contract: `protocol/signed-records.md` specifies
  `mutualbackup/storage-ack/v1`, but every signer and verifier uses
  `mutualbackup/storage-acknowledgement/v1`. Add the recovery-locator signing
  domain to the same normative table and make vectors pin both strings.
- Make `root add` perform the complete probe promised by the plan and user docs.
  The current probe checks basic `FICLONE` COW independence only; it does not
  exercise `SEEK_DATA`/`SEEK_HOLE`, verify hole preservation, survive
  rename/unlink, detect a mount-identity change, or reject nested filesystems.
- Close the process-level route evidence gap. The focused test uses real
  libp2p and proves application requests over direct, successful DCUtR, and
  retained-relay paths, but the five-daemon acceptance test only forces the
  direct path. Give its punched and relay-only peers topologies with no
  independently established direct session and assert the reported route plus
  successful backup/restore bytes.

## Accepted design and usability work

These are accepted follow-ups from design critique, not defects in the current
fixed-five profile.

- Separate human-owned daemon configuration from application-generated state.
  Keep one resolved `DaemonOptions` model for TOML and `mutualbackupd` flags,
  containing only operator choices such as paths, budgets, network policy, and
  the initial failure-domain claim. Make the config file optional, expose the
  same nonsecret options as flags, and define tested flag-over-file precedence;
  TOML paths are file-relative and flag paths are working-directory-relative.
  `mutualbackup init` and `recover-init` must not create or edit this TOML or
  mirror its deployment options. Recovery strings and derived secrets never
  enter argv.
- Move `expected_node_id` and new-versus-recovery initialization intent out of
  TOML and daemon flags into a fixed, versioned, application-owned public
  manifest under `data_dir`. `init`/`recover-init` atomically create it without
  replacement from the recovery string; the daemon requires it before unlock,
  reports its identity while locked, and checks the derived Node ID before
  opening SQLCipher. Unlock never creates or overwrites it. It remains fully
  seed-recoverable and is an accidental-mismatch guard, not protocol authority.
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
  store one output locally. Direct and hole-punched paths are preferred, but
  relay or onion fallback must retain availability. Candidate choice and
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
  distinct ephemeral encoder and verification coordinators; prefer a different
  failure domain for the verifier, while weighting reachability less because its
  traffic is small. Before encoding, the verifier commits to hidden random
  challenge material. The encoder then receives every information range once,
  signs the ordered input and output roots, and sends only each parity row to its
  holder. Holders persist the root-bound bytes as genuinely `STAGED` and sign
  storage receipts; only then may the verifier reveal a challenge derived from
  its nonce and the frozen plan, roots, and receipts. Precommit fallback
  verifiers so a timeout can inspect the same staged output without permitting
  challenge or retry grinding.
- Add a canonical range commitment and sampled-RS transcript. The current flat
  `BLAKE3(bytes)` sector root cannot prove a 16-byte range. Specify a
  domain-separated Merkle/root suite, aligned sampling and proof-leaf sizes,
  length and padding rules, proof encoding, and golden vectors. If a proof opens
  a larger leaf, transfer and check that complete leaf; a Merkle path cannot
  authenticate a bare substring that the tree did not separately commit. Every
  information and parity holder returns the same challenged range with a signed
  Merkle opening bound to the plan, attempt, root, shard index, verifier, and
  challenge. The verifier checks the openings and computes only the challenged
  RS symbols, never the complete parity rows, then publishes all openings in a
  signed, replayable audit report. Every checkpoint signer verifies that
  transcript rather than trusting a pass/fail bit. Keep staged-storage receipts,
  sampled-coding evidence, and final activation as separate protocol facts.
- State the sampling guarantee accurately. Among the 4,096 aligned 16-byte
  ranges in a 64 KiB shard, one uniformly random sample catches one bad range
  with probability only `1/4096`; its Merkle proof authenticates that sample but
  does not improve coverage of unsampled bytes. Treat this as a deliberately
  probabilistic check suited to widespread coding faults, never as proof that
  the entire codeword is valid. Pin the general miss probability and intended
  threat model in protocol tests, retain independently challenged periodic
  audits, and choose a stronger audit policy or separately reviewed proof if
  sparse adversarial corruption must be excluded.
- Make audit failure and cleanup evidence-driven. A valid opening that violates
  the RS equation attributes the committed bad row to the encoder; an invalid
  signed opening attributes the bad response to that shard holder; and a false
  verifier report is exposed by replaying its transcript. Silence or a timeout
  establishes only unavailability. After a reproducible RS mismatch, abort the
  attempt, retain the compact evidence, remove its uncommitted staged parity, and
  repeat with a fresh attempt, verifier challenge, and different encoder.
  Missing responses retry the route, holder, or verifier without needlessly
  re-encoding. Never delete already active protection until a verified
  replacement is committed.
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
