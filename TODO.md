# Source-review TODO

Source-only review of commit `0a7f7f4`. No code was built or run for this
review. This is deliberately not the roadmap: Tor, DHT replacement, hole
punching, link-freeze, watchers, repair, GC, multiple volumes, and other
explicitly delayed work are omitted.

The broad direction is good: keep the crate boundaries, deterministic
seed-derived identity, owner encryption before RS, SQLCipher as the local
container, fixed bounded sectors, and capability-probed source anchors. The
issues below are defects in behavior that is already implemented.

## P0 — fix before extending the prototype

- [ ] **Anchor cold-recovery authority in the recovering seed.**
  `GuildCheckpoint::validate` accepts a self-declared member set and
  `QuorumCheckpoint::verify` derives its quorum from that same set
  (`crates/mb-core/src/model.rs:73-95,123-153`). Network recovery accepts any
  publisher's decryptable locator, then selects the largest publisher-chosen
  generation (`crates/mb-node/src/network.rs:659-720`). A malicious peer can
  create three Sybil members, publish a generation-`u64::MAX` checkpoint, and
  eclipse the real backup. For the current all-signers slice, require the
  subject's checkpoint signature and an exact member entry containing both the
  seed-derived Node ID and recovery key. Also require the locator publisher to
  be a checkpoint member, outer and inner publishers to match, locator version
  1, and the returned checkpoint hash to equal the locator hash. Fully validate
  each candidate before ranking it; one bad high-generation candidate must not
  abort recovery. Add an attacker-eclipse regression test.

- [ ] **Make quorum signing validate a state transition, not just its shape.**
  A node currently signs any coordinator-supplied checkpoint that passes a few
  structural checks (`crates/mb-node/src/network.rs:338-340`,
  `crates/mb-node/src/node.rs:108-110`,
  `crates/mb-core/src/model.rs:73-95,227-250`). It does not check predecessor or
  generation, exact revision-to-group coverage, duplicate/conflicting IDs,
  preservation of active state, its own member/recovery-key binding, or that
  its assigned shard with the stated root is durable. It also records no
  signed-generation lock, so it will sign competing forks. Add deterministic
  semantic transition validation and persist the accepted generation/hash
  before replying. A configured coordinator may schedule work but must not be
  treated as the authority that makes an unsafe state valid.

- [ ] **Make coding-group identities and READY parity immutable.**
  Group IDs are arbitrary and are neither recomputed nor required to be unique
  (`crates/mb-core/src/model.rs:45-49,92-94,227-250`); the current group-ID hash
  omits RS/shard parameters and parity roots
  (`crates/mb-node/src/network.rs:947-960`). Storage then keys only by
  `(group_id, shard_index)` and overwrites even a READY row with different bytes
  (`crates/mb-store/src/database.rs:180-188,200-225`). Define a versioned group
  descriptor whose ID commits to the complete ordered codeword description,
  validate it, and reject duplicate IDs. An identical publish may be an
  idempotent success; any different root, length, or bytes for a READY key must
  be a hard conflict. Test that a second publish cannot destroy a recoverable
  checkpoint.

- [ ] **Turn seed recovery into recovery of an active node, for every member.**
  Rendezvous records are produced only for `peers[0]`, and recovery requires
  that member to own a revision (`crates/mb-node/src/network.rs:619-639,714-720`;
  the lab repeats this at `crates/mb-node/src/lab.rs:264,317-345`). After an
  owner restore, `rebuild_from_checkpoint` stores only the checkpoint
  (`crates/mb-node/src/node.rs:151-153`); it installs no sector recipes or
  anchors and reconstructs no parity obligation. The returned/registered node
  therefore cannot answer `GetSector` or `GetParity`. Publish recovery state for
  every member, recover state even when the member owns no revision, rebuild and
  verify all current local roles, and only then mark the node active. Test blank
  recovery of each of the five roles and use the recovered node as a shard
  source in a later recovery.

## P1 — correctness, durability, and bounded operation

- [ ] **Bind each signed revision to its encryption context and enforce its
  version.** `UserRevision` omits the guild ID/key context
  (`crates/mb-core/src/model.rs:162-171`), although preparation encrypts with a
  caller-supplied guild ID (`crates/mb-node/src/snapshot.rs:50-59`) and restore
  takes the containing checkpoint's guild ID (`snapshot.rs:224-243`). A valid
  revision can therefore be replayed into another guild, pass validation, and
  become undecryptable. Put the guild ID and current v1 cipher/sector profile in
  the signed revision, and reject unsupported revision versions before using
  any fields.

- [ ] **Move anchors out of the protected namespace and use stable addressing.**
  Anchors currently live at `source_root/.mutualbackup-anchors`
  (`crates/mb-store/src/anchor.rs:67-71`). An existing user directory with that
  name is silently chmodded and excluded, omitting it from the backup; a
  symlink can redirect the supposedly private store. Deleting the protected
  root deletes its anchors, while renaming it makes every absolute recipe path
  stale (`crates/mb-node/src/snapshot.rs:80-103,203-209`). Use an exclusively
  created, marked app directory outside the scanned tree but on the same
  filesystem, reject symlinks/name collisions, and address anchors by stable
  volume/anchor ID plus validated relative path.

- [ ] **Remove path races from reflink capture.** The walk reads metadata from a
  pathname and later reopens that pathname normally for `FICLONE`
  (`crates/mb-store/src/anchor.rs:164-188,225-243`). A rename, truncate, growth,
  or symlink substitution can clone a different inode—even a file outside the
  protected root—while the signed manifest retains the old length and
  properties; growth can be silently truncated by
  `crates/mb-node/src/snapshot.rs:83-105`. Open beneath the root with no-follow
  descriptor-relative APIs, clone from that descriptor, derive metadata from
  the captured object, and reject/retry if identity or change metadata moves
  across the capture boundary. Seal completed anchor files read-only before
  registering them; they currently remain writable (`anchor.rs:232-251`).

- [ ] **Bound recovery memory and remove the single-frame state ceiling.**
  Recovery accumulates every 64 KiB ciphertext sector in one `BTreeMap`, then
  clones sectors again during restore (`crates/mb-node/src/network.rs:733-810`;
  `crates/mb-node/src/snapshot.rs:313-325`). Preparation likewise materializes
  the metadata, references, recipes, and records, while every checkpoint embeds
  all revisions/groups and must fit the 32 MiB frame
  (`snapshot.rs:60-174`, `network.rs:24,67-71,926-944`). This makes RAM scale
  with backup size and places a hard low-gigabyte-scale ceiling on a backup.
  Stream verified recovered sectors into a durable bounded staging store, batch
  preparation writes, and page/content-address checkpoint state rather than
  serializing the whole layout into one RPC.

- [ ] **Do not multiply one dead peer's timeout by every sector.** Recovery
  probes shard holders serially for every coding group and continues through all
  five even after three valid shards are present
  (`crates/mb-node/src/network.rs:747-797`). A black-holed endpoint costs five
  seconds per 64 KiB group, turning a 1 GiB recovery into roughly 23 hours of
  avoidable waiting. Fetch with bounded concurrency, remember peer health/cut
  off repeated timeouts, and cancel the remaining reads once any three valid
  shards are available.

- [ ] **Do not issue a sole recovery pointer that expires without a refresher.**
  Commit is the only publication path and sets every locator to 30 days
  (`crates/mb-node/src/network.rs:619-638`); recovery rejects it afterward
  (`network.rs:674-679`). On day 31 an otherwise intact backup becomes
  undiscoverable. The outer directory record also has no visible generation or
  expiry, so a captured older signed record can replace a newer one
  (`network.rs:135-156,192-205`). Until renewal is implemented and tested, make
  prototype records non-expiring or reject a commit whose recovery lifetime
  cannot be maintained; add an outer monotonic anti-rollback field. Exercise
  expiry and replay with an injected clock.

- [ ] **Put hard pre-authentication resource bounds on both TCP servers.** Node
  and directory permits are held while an unauthenticated client performs an
  un-timed read (`crates/mb-node/src/network.rs:163-225,229-238`). Thirty-two
  idle sockets disable a node; accepted frames may allocate 32 MiB each before
  signature verification, and nested `Vec` lengths are not semantically
  bounded (`network.rs:24,937-944`). Add header/body/whole-request deadlines,
  small message-specific limits and nested-count limits, and bounded streaming
  for bulk data. Bound directory subjects/publishers/record size as well; its
  current unbounded maps and ignored write error permit memory exhaustion and
  oversized lookup failure (`network.rs:155-160,192-225`).

- [ ] **Do not acquire the synchronous Node mutex on a Tokio worker.** After a
  blocking request finishes, `handle_peer_connection` calls `node.lock()` on
  the async runtime in order to sign its response
  (`crates/mb-node/src/network.rs:229-250`). Another blocking worker can acquire
  that lock first and hold it through a full source capture, pinning a Tokio
  worker and potentially starving unrelated I/O and timers. Produce the signed
  response inside the bounded blocking worker, or keep a separately usable
  signer; no blocking mutex acquisition belongs in async code.

- [ ] **Authorize reads and bind signed requests to their destination and
  protocol context.** `GetSector`, `GetParity`, and `GetCheckpoint` are accepted
  from any valid signing key, not an authorized guild member
  (`crates/mb-node/src/network.rs:85-99,259-297`). The signed request contains
  only a request ID and enum (`network.rs:102-106`), so a captured mutation can
  be forwarded to another node that trusts the same coordinator. Add an
  explicit wire version, intended recipient, guild/authorization scope, caller,
  and freshness context to the signed bytes; enforce membership/capability per
  operation before touching storage.

- [ ] **Finish crash durability before reporting capture or recovery success.**
  Capture and restore fsync files but not all modified nested directories;
  restored modes are changed after the last file fsync
  (`crates/mb-store/src/anchor.rs:82-84,188,250,272-276`;
  `crates/mb-node/src/snapshot.rs:257-259,288-309,369-373`). Recovery publishes
  the restored target before it persists even the incomplete rebuilt state
  (`crates/mb-node/src/network.rs:721-730`), so a later failure leaves a target
  that blocks retry. The earlier `target.exists()` check and plain `fs::rename`
  are also a race that can replace an entry created in between
  (`crates/mb-node/src/snapshot.rs:235-259`). Fsync modified directories
  bottom-up and inode metadata after chmod, journal recovery, make retry
  idempotent, persist verified node state/roles before an atomic no-replace
  target rename, and clean or adopt staging/final anchors on every later error
  path.

- [ ] **Write the recovery seed atomically and directory-durably.** `init`
  writes directly to the final `create_new` file and fsyncs only that file
  (`cmd/mutualbackup/src/main.rs:182-195`). Interruption can leave a truncated
  final seed that cannot be replaced, and a crash may lose the directory entry
  after success was printed. Write and validate a mode-0600 temp file in the
  same directory, fsync it, install it with no-replace semantics, then fsync the
  parent directory.

- [ ] **Lock one data directory to one live Node and make operation replay truly
  stable.** `Node::open` retains no process lock (`crates/mb-node/src/node.rs:23-38`).
  Two daemons can therefore interleave a side effect and the later operation
  cache write (`crates/mb-node/src/network.rs:280-294`), while client retries
  always generate a fresh UUID (`network.rs:840-853`). Hold an OS lock for the
  Node lifetime. Persist coordinator operation IDs across retries, bind cached
  entries to request kind/hash/caller, and make same-database effects plus their
  result atomic; reconcile cross-database effects after crashes.

## P2 — format and fidelity defects to close before compatibility promises

- [ ] **Enforce database kind and schema version on open.** Control storage only
  inserts version 1 if absent and never reads it; parity storage has no database
  identity/version metadata (`crates/mb-store/src/database.rs:37-59,179-189`).
  `CREATE TABLE IF NOT EXISTS` can consequently operate on an incompatible or
  newer database. Validate kind/version before mutation, reject unknown newer
  versions, and run explicit transactional migrations.

- [ ] **Stop silently claiming filesystem entries/properties that are not
  restored.** Capture skips the source-root entry and silently ignores anything
  that is neither a directory nor a regular file
  (`crates/mb-store/src/anchor.rs:161-200`), so the restored root stays mode 0700
  and FIFOs/sockets/devices vanish. File modification times are carried through
  private metadata but ignored by the restore match
  (`crates/mb-node/src/snapshot.rs:15-29,277-303`). Apply the properties already
  recorded, including root mode/time, and fail capture explicitly on unsupported
  object types rather than reporting a complete backup.

- [ ] **Define one canonical checkpoint state identity.** Verification accepts
  signatures in any order and accepts any quorum-or-larger subset, while
  `hash()` includes that vector (`crates/mb-core/src/model.rs:113-159`). Reordering
  or adding a valid surplus signature changes the locator hash without changing
  the authorized state. Hash the canonical checkpoint body as the stable state
  ID and carry a separately normalized quorum certificate, or enforce one exact
  sorted certificate representation. Enforce canonical ordering/uniqueness for
  all set-like vectors too.

- [ ] **Reject weak Ed25519 and non-contributory X25519 inputs.** Incoming
  signatures use non-strict Ed25519 verification
  (`crates/mb-core/src/model.rs:140-145,190-196`), and recovery-record DH never
  checks `SharedSecret::was_contributory()`
  (`crates/mb-core/src/recovery.rs:47-55,84-91`). Use strict verification,
  reject weak member keys, and reject low-order recovery/ephemeral keys before
  deriving an AEAD key. Add crafted edge-case vectors.

- [ ] **Make the claimed recovery invariant a mandatory test, not an optional
  pass.** The only in-process recovery test returns successfully when
  `MUTUALBACKUP_REFLINK_TEST_ROOT` is absent
  (`crates/mb-node/src/lab.rs:503-510`), covers only a small honest owner-0
  recovery, and then never asks the recovered node for a shard
  (`lab.rs:525-549`). The network module otherwise tests only endpoint parsing
  (`crates/mb-node/src/network.rs:982-993`), and the Nix package disables checks
  (`flake.nix:10-18`). Make the reflink-backed acceptance suite an explicit
  required CI job and cover the hostile/restart/post-recovery cases named above;
  a missing test filesystem must skip visibly at the harness level, not turn the
  test green from inside the test body.

- [ ] **Reject unusable advertised endpoints before committing data.** Server
  startup validates neither the syntax nor identity reachability of
  `public_endpoint` (`crates/mb-node/src/network.rs:163-167`), and commit trusts
  the returned string (`network.rs:411-420`) even though it becomes the sole
  locator endpoint. A typo produces a successful commit that recovery cannot
  use. Parse at startup and have commit verify enough advertised endpoints by
  connecting and authenticating the expected Node IDs before it reports
  success.
