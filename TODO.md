# Source-review TODO

Source-only review of `9a31da9` plus the current working tree. Nothing was
built or executed for this review. This is not the roadmap: Tor, DHT
replacement, hole punching, link-freeze, watchers, repair, GC, and multiple
volumes are intentionally omitted. Every item below is a defect in behavior or
state already implemented.

## P0 — protection can be falsely certified or checkpoint progress can wedge

- [ ] **Prove the Reed--Solomon relation before signing a checkpoint.**
  `GuildCheckpoint::validate` commits to five roots but never proves that the
  two parity shards encode the three declared information shards
  (`crates/mb-core/src/model.rs:412-468`). A parity holder merely checks that
  the arbitrary bytes supplied by the coordinator match the coordinator's
  root, and every node validates only its own local shard
  (`crates/mb-node/src/node.rs:326-353`,
  `crates/mb-node/src/network.rs:760-833`). A buggy or malicious coordinator
  can therefore obtain a fully signed checkpoint whose parity is useless after
  an information-shard loss. Have parity holders derive/verify their row from
  authenticated information shards (or add an equally strong coding proof),
  and add a corrupt-but-self-consistent parity regression test.

- [ ] **Bind every revision sector to its signed owner in coding-group
  validation.** Revision coverage is indexed only as `SectorId -> SectorRef`;
  when a matching reference appears in a group, the validator does not require
  `InformationRole.owner` to equal the revision owner
  (`crates/mb-core/src/model.rs:145-184,412-468`). The real owner also checks
  only roles assigned to itself before signing (`crates/mb-node/src/node.rs:326-353`).
  A quorum certificate can thus cover Alice's signed metadata sector while
  assigning it to Bob; Alice accepts and cold recovery later installs no recipe
  for that sector. Carry `(owner, reference)` through validation and require an
  exact one-to-one owner-preserving assignment.

- [ ] **Do not overwrite an uncommitted signature lock with its child.** A node
  may sign generation `N+1` using its generation-`N` lock even when `N` is not
  yet the committed head (`crates/mb-node/src/node.rs:274-323`). The database
  then replaces the sole lock row with `N+1`
  (`crates/mb-store/src/database.rs:467-519`). A late finalize of `N` fails
  because its lock vanished, while finalize of `N+1` fails because head `N`
  was never installed (`database.rs:523-586`). Network reordering can therefore
  wedge that guild permanently. Retain per-generation locks and finalize in
  order, or refuse to sign a child until its parent certificate is committed.

## P1 — correctness, durability, availability, and bounded operation

- [ ] **Validate revision lineage instead of trusting sequence labels.** The
  model only checks that sequence 1 has no parent and later sequences have some
  parent; it permits gaps, duplicate `(owner, sequence)` values, and arbitrary
  parent hashes (`crates/mb-core/src/model.rs:145-184`). Recovery then chooses
  whichever revision has the largest sequence without validating a chain
  (`crates/mb-node/src/network.rs:1036-1048`,
  `crates/mb-node/src/lab.rs:330-343`). Define the signed revision identity,
  require each owner's head to extend its exact predecessor, reject forks and
  duplicate sequences, and select only the authenticated head.

- [ ] **Journal the coordinator's whole commit, not only individual peer
  calls.** Every invocation chooses a fresh random guild ID and retains no
  durable coordinator state (`crates/mb-node/src/network.rs:650-700`). Failure
  after source capture, parity publication, signature locking, checkpoint
  finalization, or partial directory publication cannot resume the same
  transaction; rerunning starts a different guild and strands anchors, parity,
  pages, and locks. Persist the draft guild/checkpoint, peer operation IDs, and
  phase before the first side effect, then resume or explicitly abort that same
  operation.

- [ ] **Finish the bounded-state design; paging currently changes only the
  wire envelope.** `PrepareSource` still returns the complete revision in one
  600 KiB frame, imposing a backup-size ceiling in the hundreds of MiB
  (`crates/mb-node/src/network.rs:28,171-188,705-725`). Preparation constructs
  all private entries/references and serialized metadata in memory
  (`crates/mb-node/src/snapshot.rs:103-200`); checkpoint fetch and staged
  assembly concatenate the entire object, with additional copies during decode
  (`network.rs:1225-1272`, `crates/mb-store/src/database.rs:366-414`); restore
  concatenates all private metadata (`snapshot.rs:380-390`). Page revision
  catalogs and metadata too, decode/validate incrementally, and enforce a small
  end-to-end memory budget rather than a 256 MiB object cap with several live
  copies.

- [ ] **Keep synchronous filesystem/SQLCipher work off Tokio workers and split
  the global node lock.** Server requests run in `spawn_blocking`, but hold one
  `Mutex<Node>` across an entire capture or store operation, so one long
  capture serializes all reads and parks other blocking-pool jobs
  (`crates/mb-node/src/network.rs:359-451,495-633`). The async recovery client
  directly performs synchronous SQLCipher writes, checkpoint installation, and
  the complete filesystem restore on its runtime thread
  (`network.rs:1034-1048,1152-1159`). Use bounded DB/filesystem/CPU workers with
  short ownership scopes; do not make the whole node one blocking critical
  section.

- [ ] **Do not leave recovered owner data permanently embedded in
  `control.db`.** Recovery decrypts every information sector and installs it as
  an inline plaintext recipe (`crates/mb-node/src/node.rs:424-465`,
  `crates/mb-node/src/snapshot.rs:269-290`). Restore writes a second copy to the
  target, but no successful transition replaces those inline rows with recipes
  backed by a durable source anchor. An active recovered owner therefore turns
  the control database into a full duplicate data store. Build and fsync the
  restored anchor, atomically switch recipes to it, and retire recovery payload
  rows only after the switch is durable.

- [ ] **Make anchor IDs locatable and make capture cleanup complete.**
  `AnchorAreaLocator` has an ID, but opening an anchor only validates and uses
  its absolute `path_hint`; renaming a parent makes every committed recipe
  unavailable even though the anchor moved intact
  (`crates/mb-store/src/anchor.rs:58-80,349-360,477-482`). Capture also leaks its
  staging directory when bottom-up sync or the no-replace rename fails
  (`anchor.rs:138-153`), and its sync walk silently drops traversal errors
  (`anchor.rs:654-666`). Resolve the stable area/volume ID through local catalog
  state, guard the complete capture with cleanup/reconciliation state, and
  propagate every sync-walk error.

- [ ] **Preserve filesystem semantics that the current capture accepts.**
  Regular hard-linked aliases are captured as unrelated files because no
  native identity/link relation is recorded; recovery always creates a new
  inode per path (`crates/mb-store/src/anchor.rs:226-301`,
  `crates/mb-node/src/snapshot.rs:426-474`). Sparse extents are likewise read as
  zero bytes into sectors and restored with dense `write_all`, so a large sparse
  file can exhaust the target disk (`snapshot.rs:124-169,448-474`). Either
  preserve link groups and hole maps in signed private metadata or reject such
  inputs explicitly; do not silently report a faithful restore.

- [ ] **Retry directory durability before adopting a published restore.** If
  `rename_no_replace` succeeds but the parent-directory fsync fails,
  `publish_restore` returns an error while the job remains `Ready`
  (`crates/mb-node/src/snapshot.rs:404-408`,
  `crates/mb-node/src/node.rs:575-582`). On retry, the existing-target branch
  checks only `(dev, ino)`, marks the job `Complete`, and never retries that
  fsync (`node.rs:547-557`). Sync the parent before durable adoption and bind
  adoption to a stronger persisted marker/manifest so inode reuse cannot make
  an unrelated directory look owned by the job.

- [ ] **Do not bless unknown or malformed database layouts during migration.**
  Versions 3 and 4 are upgraded largely by `CREATE TABLE IF NOT EXISTS` plus a
  version bump; current-version validation checks table names, not their
  columns, constraints, or indexes (`crates/mb-store/src/database.rs:917-1027,1168-1179`).
  Version 4 was never a committed schema. Parity versions 2--4 are relabeled
  current without validating `parity_objects`, while the v1 path hides all old
  rows in `parity_objects_v1_unassigned` and then opens an empty active store
  (`database.rs:1030-1100`). Define and test every accepted source schema
  exactly; reject undefined layouts, and require explicit reconciliation when
  legacy parity cannot be assigned safely.

- [ ] **Close the remaining server and directory resource-exhaustion paths.**
  Reads have deadlines, but server response writes do not; clients that stop
  reading can retain all node/directory permits indefinitely
  (`crates/mb-node/src/network.rs:238-371,1406-1418`). Directory admission also
  permits 64 records of up to 64 KiB each even though serializing those records
  plus envelope overhead exceeds its 4 MiB response limit
  (`network.rs:29-32,274-330,339-354`). Add a whole-connection/write deadline
  and make admission limits prove that every accepted lookup result is
  returnable within its frame and memory budgets.

- [ ] **Prevent trivial Sybil saturation of recovery rendezvous slots.** The
  directory accepts any self-signed key as a publisher for any subject before
  the encrypted inner record can prove guild membership. An attacker can fill
  the first 64 publisher slots for a known Node ID (or all 100,000 subject
  slots), after which legitimate peers are rejected
  (`crates/mb-node/src/network.rs:230-235,274-330`). Because cold recovery
  depends on these records, this is an availability break, not authority over
  recovered state. Admission/eviction must not grant scarce slots to the first
  unauthenticated identities that write them.

## P2 — format, interface, and verification defects

- [ ] **Do not expose or conflate guild recovery records in the directory
  schema.** `PublishedRecoveryRecord` leaves guild ID, checkpoint hash, and
  generation in cleartext, contrary to the opaque rendezvous design
  (`crates/mb-node/src/network.rs:205-215`). Records are keyed only by
  `(subject, publisher)`, so the same two nodes' records for different guilds
  overwrite or reject one another as forks (`network.rs:230-231,294-326`). Use
  a privacy-preserving, independently versioned slot/anti-rollback key that can
  represent every guild without revealing the decrypted locator fields.

- [ ] **Align protocol integer ranges with persistence.** Checkpoint validation
  accepts every nonzero `u64` generation, while signature locking and commit
  convert it to SQLite `i64` and reject values above `i64::MAX`
  (`crates/mb-core/src/model.rs:113-123`,
  `crates/mb-store/src/database.rs:467-476,523-534`). A quorum-valid wire object
  can therefore be impossible to persist. Constrain the wire model or store the
  full unsigned representation consistently.

- [ ] **Make `recover --restore` truthful for members without a user
  revision.** Recovery intentionally rebuilds parity/helper roles too, but if
  the seed owns no revision it returns success without creating the requested
  target (`crates/mb-node/src/network.rs:1034-1050`). The CLI nevertheless
  always prints `restored directory` (`cmd/mutualbackup/src/main.rs:164-178`).
  Make restoration optional for storage-only recovery, or fail an explicitly
  requested restore when there is no recoverable user revision.

- [ ] **Make the mandatory acceptance coverage exercise the claimed failure
  boundary.** The network acceptance test removes only the recovered owner, so
  four remote shards remain, and it exercises only the owner role
  (`crates/mb-node/src/network.rs:1574-1665`). The in-memory all-role test also
  keeps four remote nodes available for each recovery
  (`crates/mb-node/src/lab.rs:597-665`). Add a required real-network case with
  the recovered node plus one other failure, use recovered nodes as later
  sources, and cover the invalid-parity, role-owner, lock-reordering, migration,
  sparse-file, and interrupted-restore cases above. Also update `README.md:81-83`:
  setting the environment variable alone no longer runs tests now marked
  `#[ignore]`; the explicit acceptance script is required.
