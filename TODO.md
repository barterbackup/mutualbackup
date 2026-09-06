# Source-review TODO

Source-only re-review of the fixes through `1696e18`. No build, test, or
runtime probe was performed. Resolved findings have been removed; this file
contains only high-confidence defects in behavior already implemented. Roadmap
work such as Tor, DHT replacement, hole punching, link-freeze, watchers,
repair, GC, and multiple parity volumes remains intentionally omitted.

## P0 — protection can be lost or falsely reported

## P1 — correctness, durability, availability, and resource bounds

- [ ] **Journal source capture and its database records as one recoverable
  transition.** A durable anchor is installed before any intent naming it is
  persisted; sector recipes are then committed in 256-row batches, separately
  from the manifest, revision, and head
  (`crates/mb-node/src/snapshot.rs:94-110,152-163,335-356,437-450`). A process
  crash can leave an undiscoverable anchor, while a later preparation error can
  remove the anchor but leave dangling `local-sector` rows. Persist a pending
  capture before materialization and either finalize atomically or reconcile
  all rows and anchor directories on retry/startup.

- [ ] **Recover guilds independently instead of comparing their generations.**
  The commit and directory paths can create and retain distinct guilds for the
  same seed, as the design permits, but recovery puts every valid checkpoint
  into one vector and chooses one global maximum generation
  (`crates/mb-node/src/network.rs:1425-1509`). Generations are ordered only
  within a guild; two ordinary generation-1 guilds make the selected restore
  depend on record order, and all other guild state is discarded. Resolve a
  head per guild and rebuild every guild, with an explicit restore-target
  policy rather than an arbitrary cross-guild maximum.

- [ ] **Turn storage-member recovery into a real rejoin path.** The routine
  that rebuilds a storage-only member is private, while the exported API and
  CLI require an owned revision and restore target
  (`crates/mb-node/src/lib.rs:10-14`; `crates/mb-node/src/network.rs:1382-1419`;
  `cmd/mutualbackup/src/main.rs:162-176`). The chained test reaches the private
  routine and then reuses each dead node's exact old socket address
  (`network.rs:2477-2528`). There is also no way to republish the recovered
  member at a new endpoint: endpoint-only changes produce a different sealed
  record at the same checkpoint generation, which the directory rejects as a
  fork (`network.rs:509-529,898-948`). Expose state-only recovery and let a
  recovered member durably publish a separately versioned current endpoint
  before treating it as an active recovery source.

- [ ] **Allow a recovered node to reproduce its signature for its installed
  checkpoint.** Recovery installs a checkpoint head without restoring a
  signature lock (`crates/mb-node/src/node.rs:610-673`). The transition layer
  accepts an identical generation/hash, but `lock_checkpoint_signature`
  rejects that request when a head exists and no lock does
  (`node.rs:494-495`; `crates/mb-store/src/database.rs:474-532`). Retrying the
  original coordinator journal after a helper was seed-recovered therefore
  wedges at `SignCheckpoint`. Recreate the exact matching lock/signature from
  authenticated recovered state, without permitting a same-generation fork.

- [ ] **Do not permanently blacklist a holder after one recovery read
  failure.** Normal peer mutations receive a bounded retry, but shard recovery
  calls `send_peer_request` only once and adds the holder to a recovery-wide
  `unhealthy` set after any transport, timeout, or response error
  (`crates/mb-node/src/network.rs:1562-1603,1883-1898`). At the advertised
  recovered-node-plus-one-peer failure boundary, exactly three remote shards
  remain, so one transient error makes a reconstructable group fail. Retry
  transient failures under a bounded budget and distinguish connectivity from
  authenticated corrupt data before opening a circuit for that holder.

- [ ] **Do not cache deterministic filler payloads in the operation journal.**
  Each `EnsureFiller` response contains a full 64 KiB shard
  (`crates/mb-node/src/network.rs:818-825,1640-1664`), and generic mutation
  caching serializes that response permanently into `operations`
  (`network.rs:645-666`; `crates/mb-store/src/database.rs:105-184`). At the
  supported 40,000-group limit, each of the two filler peers stores roughly
  2.6 GiB of reproducible payload in `control.db`, defeating the payload-free
  filler recipe. Cache only a compact descriptor and recompute the bytes on
  replay, with a bounded operation-cache lifecycle.

- [ ] **Retry staged-page cleanup after checkpoint finalization.** Checkpoint
  storage and deletion of its staged body/certificate pages are separate
  transactions (`crates/mb-node/src/node.rs:443-452`). If the process or delete
  fails after the checkpoint commit, the retry's existing-checkpoint fast path
  returns before cleanup (`node.rs:438-442`), permanently retaining as much as
  about 64 MiB per node per interrupted finalization. Clear matching pages in
  the idempotent path or commit/retire them as one recoverable transition.

- [ ] **Protect global directory capacity from attacker-owned subjects.** A
  subject signature protects an honest subject's slots, but an attacker can
  create its own subject and publisher keys, self-authorize them, and consume a
  permanent subject entry after only 16 bits of fixed work
  (`crates/mb-node/src/network.rs:32-41,352-436`). Once 100,000 such subjects
  exist, every new legitimate subject is rejected, and all accepted records
  are required to use `u64::MAX` expiry (`network.rs:366-379,492-497`). Enforce
  a global byte budget with expiry/eviction and a rate/admission policy tied to
  that scarce resource; fixed test-strength proof of work is not sufficient.

- [ ] **Bound directory memory by bytes, not only connection count.** Both
  lookup and publish use the 4 MiB response limit as their inbound request
  limit, although a publishable record is capped at 64 KiB
  (`crates/mb-node/src/network.rs:29-35,467-486`). `read_frame_timed` allocates
  the advertised buffer before authentication or decoding, so 128 slow clients
  can reserve about 512 MiB (`network.rs:1969-1983`). Concurrent lookups can
  additionally clone and serialize near-4-MiB mailboxes
  (`network.rs:555-560,1944-1966`). Use request-specific limits and a shared
  weighted byte semaphore for inbound and response buffers.

- [ ] **Use an indexed persistent anchor/volume locator in the sector hot
  path.** The supposedly stable locator stores only `st_dev` and an absolute
  volume-root hint (`crates/mb-store/src/anchor.rs:98-104,477-494`), so a
  remount at a new path or device number makes an intact anchor undiscoverable.
  After a simpler parent rename, every 64 KiB sector open independently walks
  the complete filesystem and never caches the resolved area
  (`anchor.rs:113-118,521-553`;
  `crates/mb-node/src/snapshot.rs:902-928`). Resolve a persistent authenticated
  volume/area UUID once through local catalog state, persist the new path hint,
  and never perform a full-volume search per sector.

## P2 — format, privacy, and authorization defects

- [ ] **Compare SQL schemas without rewriting quoted literals.** The exact
  schema validator removes whitespace and lowercases every character, including
  string literals (`crates/mb-store/src/database.rs:1168-1201`). It therefore
  accepts an `operations` constraint containing `'in_progress'` and
  `'committed'` as equivalent to the required uppercase states, even though all
  normal inserts then violate that constraint (`database.rs:1072-1079`). It
  also ignores non-table schema objects such as triggers. Compare parsed schema
  facts or tokenize SQL while preserving literal contents, and reject
  unexpected behavior-bearing objects.

- [ ] **Encode pre-epoch modification times correctly.** The fractional
  pre-1970 branch computes `-(seconds.saturating_sub(1))` instead of
  `-seconds-1` (`crates/mb-store/src/anchor.rs:895-912`). Thus `-0.5s` is stored
  as `+0.5s`, and multiple distinct old timestamps collapse to the same value.
  Produce the normalized signed `(seconds, nanoseconds)` pair with checked
  arithmetic and add boundary vectors around the Unix epoch.

- [ ] **Bind prepared-revision page reads to the authorized guild.** The server
  authorizes `GetPreparedRevisionPage` using the request's `guild_id`, but the
  read handler discards that field and fetches solely by `revision_id`
  (`crates/mb-node/src/network.rs:608-624,751-761`;
  `crates/mb-node/src/node.rs:128-137`). A member authorized in guild A can
  retrieve a known revision catalog belonging to guild B from a node in both.
  Load and validate the signed revision's guild before returning any page, or
  key persisted revisions by guild as well as revision ID.

- [ ] **Do not expose checkpoint generation through the opaque rendezvous
  wrapper.** Guild ID and checkpoint hash are now sealed, but the public
  `slot_generation` is assigned the exact checkpoint generation and recovery
  requires equality (`crates/mb-node/src/network.rs:261-271,937-948,1441-1453`).
  The directory can therefore observe each hidden guild slot's checkpoint
  count and update cadence. Use an independently versioned anti-rollback token
  that does not copy a decrypted locator field into cleartext.
