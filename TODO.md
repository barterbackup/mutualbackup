# Product TODO

## Milestone 2 corrective gate

The Milestone 2 implementation is present, but a follow-up source-only review
found the concrete defects below. These are mistakes in current behavior or
coverage, not delayed product features. Fix and remove them before beginning
Milestone 3. Several invalidate inherited Milestone 1 stabilization claims, so
they belong to the current exit gate rather than being deferred.

- Make initialization reject an unsuitable data directory without changing it.
  `ensure_empty_private_data_dir` currently changes an existing directory to
  mode `0700` before discovering that it is nonempty, so a failed `init` can
  silently alter an unrelated user directory. Check type, ownership, and
  emptiness before mutation; safely create and sync a missing private directory.
- Make the seed-plus-identity initialization workflow recoverable from every
  partial result. `init --seed-file` installs the seed before the identity
  manifest, and the private-file helper can leave a temporary or an installed
  target while returning an error. A retry then collides with no-replace state.
  Define how a byte-identical installed output is resumed, remove only verified
  app-owned temporary files, and add process-level interruption and no-replace
  cases. The Docker lab must not reinterpret `seed exists, manifest absent` as
  proof that a never-created node is a cold-recovery node.
- Complete mixed-source override semantics. A command line can replace a TOML
  `seed_file` or nonempty address list, but cannot explicitly unset the seed file
  or clear `listen`, external, bootstrap, or relay addresses. Add unambiguous
  clear/unset flags and precedence cases, especially a way to override
  unattended auto-unlock with locked startup.
- Resolve relative TOML paths against the config pathname supplied by the
  operator, not the canonical target of a symlink. Canonicalizing the config
  before choosing its base changes the meaning of a symlinked configuration—for
  example, an `/etc` link into a read-only Nix store—and contradicts the stated
  “relative to this config file” rule. Pin and test the symlink policy.
- Make cold recovery adoption idempotent across endpoint churn. Recovery writes
  an `InstalledGuild` containing live endpoint hints before it retrieves shards
  or installs the checkpoint, then rejects a retry unless the newly discovered
  endpoint vector is byte-identical. Keep the certified genesis/member roster
  as immutable authority, store mutable endpoints in a mergeable cache, and
  prove that an interrupted recovery resumes after endpoints or availability
  change.
- Do not acknowledge unlock or print `ready` until the configured network mode
  has actually reached its startup condition. Building the swarm only schedules
  listeners; port conflicts and later listener closure are merely logged, so a
  daemon can report ready with no usable inbound listener or relay reservation.
  Surface per-transport readiness/degradation and supervise failure before Arti
  adds another transport lifecycle.
- Make the Docker lab verify mount provenance before using or unmounting an
  already-mounted node path. Checking only `mountpoint` plus `btrfs` accepts an
  unrelated Btrfs filesystem at that path. Require the source loop device to be
  associated with that node's exact image and reject every mismatch.
- Make Docker `up` resume partial guild finalization. Genesis is installed on
  remote members before the coordinator; interruption can therefore leave a
  Draft coordinator and Active peers, which `ensure_guild` currently treats as
  an unrecoverable phase combination even though reinstalling the same
  certificate is idempotent.
- Make connectivity acceptance attribute bytes to the operation and path under
  test. It currently accepts old cumulative byte counters plus the peer's latest
  path label, and a later successful DCUtR event can retroactively relabel a
  prior direct application path. Capture counter baselines or operation-scoped
  telemetry and prove that each tested backup/restore payload—not merely some
  earlier request—used the forced direct, punched, or retained-relay route.
- Provide a reproducible source-defined handoff from the Nix package to the two
  filenames consumed by the guides and Docker lab. `nix build` produces normal
  `result/bin` entries, while the documented ignored `dist/*-x86_64-linux`
  artifacts are currently populated only by an undocumented manual step. Add a
  release/export target or teach the lab and documentation to consume an
  explicit package result without building it.

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
