# Product TODO

## Milestone 6 corrected production plan — 2026-10-05

FUSE-backed guarded storage was added in error and is removed from the target
architecture. The first withdrawal step removes enrollment commands and rejects
identified legacy guarded state before catalog migration or replay. The source
no longer contains the mount runtime or its dependency; R1 remains open. Stop
FUSE feature work, including retained-descriptor recapture isolation, guarded
Git enrollment/checkout, metadata fidelity, edit guards, and mount qualification.
Their earlier work and test evidence are archived below, with unfinished work
marked canceled rather than completed. Implement removal through R1, then close
the non-FUSE correctness, capacity, operations, and release gates below.

The supported design continues to use native immutable capture/clone facilities,
with Linux reflink as the implemented backend and Windows NTFS/VSS and macOS
clone backends still planned. Reject unsupported filesystems explicitly; do not
replace FUSE with a new mounted view or silently copy full file payloads. Keep
exact Git bytes, recoverable retention/prune, seed-only recovery where promised,
and versioned local/wire compatibility as production requirements. Historical
passing tests below apply only to their recorded source and exercised cases.

- [ ] **R1 / P1 — Remove the FUSE-backed guarded product and define safe upgrade
  behavior.** Inventory guarded/FUSE store modules, dependencies, mount and
  supervision code, daemon startup/replay hooks, root enrollment/removal and Git
  control/CLI paths, recovery integration, acceptance scripts, packaging, and
  documentation. Remove those product paths and stop advertising or accepting
  new guarded roots. Inventory existing guarded roots, captures, Git catalogs,
  pins, pending intents, and signed revisions before choosing an upgrade policy.
  Implement a verified export/migration path to a supported native backend, or
  explicitly reject an unsupported existing state before mutation with an
  actionable recovery/export procedure. Preserve all user bytes, anchors, Git
  history, revision pins, and signed protection until replacement is verified;
  deleting code never authorizes deletion of protected data or mount-backed
  directories. Do not reinterpret a guarded catalog as reflink. Retain minimal
  legacy decoding or an isolated export reader wherever needed to identify and
  recover historical formats; keep enum discriminants and serialized identities
  stable rather than renumbering them after removing variants. Shared code stays
  only where a supported native path requires it. Acceptance: fresh installations
  expose no FUSE enrollment, mount, or runtime dependency; upgrade fixtures with
  live/history-only Git data, interrupted intents, and retained revisions either
  export/migrate exact bytes and history durably or fail before any mutation.
  Restart and source-loss recovery exercise the stated legacy policy. Replace
  useful generic recovery/prune coverage from deleted FUSE fixtures under R7.

  - [x] Remove guarded enrollment/removal and guarded-only Git retirement from
    CLI help; reject their legacy local requests. Inspect existing encrypted
    catalogs read-only before rekeying, schema migration, operation cleanup,
    capture replay, or remount. Reject guarded record prefixes, protected-root
    format 4, backend bindings, and pending capture/recovered-anchor plans.
    Preserve enum identities and reject guarded source-loss enrollment before
    publishing a recovery job. Document preservation and current migration
    limits in [the withdrawal procedure](docs/guarded-withdrawal.md).
    Validation: locked workspace tests; read-only SQLCipher, startup/admission,
    legacy capture/recovery-intent, and CLI withdrawal tests; native Btrfs Git
    reopen/commit, backend reprobe/migration, relocated recovery, encrypted Git
    history, and legacy intent migration regressions. Format and strict Clippy
    pass with unrelated pre-existing FUSE test WIP held aside and restored.
  - [x] Extend read-only admission to registered history-only Git catalogs:
    inspect backend bindings, guarded journals, and root-backed blob manifests
    without replay or unbound-catalog migration. Inspect authenticated local
    metadata headers in retained user revisions, revision heads, and certified
    checkpoints, detecting formats 6/7 even when later sectors are unavailable.
    Pending Git graph intents with root-backed blobs are rejected before cleanup.
    Durable backend dispatch also rejects legacy root/file capture, edit,
    replay, discard, and blob-import planning without touching source or anchors;
    their serialized enum identities remain unchanged.
    Offline catalogs and metadata not yet downloaded remain subject to recovery
    admission; this does not certify migration or historical export.
    Validation: read-only native/unbound and historical Git catalog fixtures,
    history-only startup fixtures preserving database/key/parity/source bytes,
    signed revision/head/checkpoint rejection fixtures, and literal streaming
    catalog scans. Locked workspace tests: 691 passed, zero failed, 182 ignored
    across 19 targets. Format and strict workspace/all-target Clippy pass with
    the unrelated pre-existing FUSE test WIP held aside and restored byte-for-byte.
    Five native Btrfs regressions pass: Git reopen/add, linked worktree reopen,
    signed-history prune, backend reprobe/migration, and seed-only branch/blob
    recovery. The disposable mount and image were removed after qualification.
  - [x] Remove the FUSE runtime/dependency, mount supervisor, guarded capture
    and publication, guarded Git operations, and link-freeze machinery. Retain
    minimal legacy record decoding and marker recognition. Inspect ordinary and
    linked-worktree stage journals before unbound-catalog migration. Preserve
    pre-existing test WIP in `.git/preserved-wip/2026-10-06-fuse-removal/`.
    Native recovery verifies recovered Git refs, objects, exact blob bytes,
    authenticated sector recipes, and sparse gaps before root registration.
    Generic seed recovery, retention/prune, and repeated owner-loss coverage
    now use the native backend.
    Validation: locked workspace tests passed (611 passed, zero failed, 105
    ignored across 27 targets including doctests); format and strict all-target
    Clippy passed. The complete `git-linux-acceptance.sh` gate passed on disposable
    Btrfs: 73 provisioned tests, including both owner losses and the five-daemon
    direct/hole-punch/relay topology. The qualified source manifest and binary
    hashes matched; the disposable filesystem and network resources were cleaned
    up. The Cargo dependency tree contains no `fuser`.
  - [x] Recognize marker-only historical single-file captures before Git catalog
    initialization, reopening, or unbound-backend migration, including catalogs
    with a native binding. Ordinary native blob verification also rejects those
    ownership markers and root-backed legacy manifests. Reject unavailable
    provenance before migrating an unbound catalog; retain unavailable native
    copies for repair in an already bound catalog. Only the binding stored under
    this repository's key establishes native ownership; a misplaced record does
    not authorize migration.
    Validation: locked workspace tests passed (613 passed, zero failed, 105
    ignored). Disposable Btrfs regressions passed all 70 provisioned Git, extent,
    daemon reopen, retention, migration, and recovery checks, including two owner
    losses and physical history reclamation. The final binding-key hardening is
    covered by the ordinary Git preservation fixture; format and strict
    workspace/all-target Clippy pass. The disposable mount and image were removed.
  - [x] Add a mount-free Linux export for available authenticated historical
    private formats 6/7. `mutualbackup legacy-export` reads a canonical signed
    revision and exact ciphertext sector files, authenticates owner/writer,
    roots/commitments and complete private-to-signed data joins before creating
    output. It preserves recorded raw paths, sparse file lengths/gaps, hard
    links, ownership, modes and timestamps in a separate namespace. Format 7
    also streams and hash-verifies every reachable blob/object into a stock Git
    bare repository with all refs and primary HEAD. It records signed provenance
    and an export report, flushes output, and publishes the package using a
    no-replace rename. Original control catalogs, bindings, journals, native
    anchors and peer-held history are not opened or retired. Missing/corrupt
    metadata or sectors fail; failed construction leaves no published target.
    Crash staging remains private for inspection. Four library fixtures and
    one actual offline CLI fixture pass, including raw paths, hard links,
    sparse/ownership/timestamp checks, exact Git refs/objects, stock Git strict
    fsck, unchanged inputs, missing/corrupt/changing sources, input symlinks,
    wrong blob length/OID, nonempty destinations and absent daemon socket.
    Peer recovery and original-anchor extraction,
    complete retained-revision conversion and legacy upgrade/source-loss gates
    remain open. Export alone does not certify replacement protection or safe
    retirement; absent legacy ACL/xattr metadata cannot be reconstructed.
    Validation: all 104 core, 101 ordinary store, 87 ordinary Git, 368 ordinary
    Node and 16 CLI-library tests pass, plus three CLI and seven mutualgit unit
    tests and the real offline export CLI fixture. All eight provisioned snapshot
    regressions pass on disposable Btrfs with verified mount/image/loop cleanup.
    Formatting and strict workspace/all-targets Clippy pass. The final export
    guard rejects oversized revision bodies before signature encoding/fetch.
    Ordinary suites retain 18 store, 62 Git and 20 Node provisioned cases; only
    the eight snapshot cases above ran separately. Full M6 release gates remain
    open, including real historical upgrade/source-loss and all retained history.
  - [x] Add read-only original-catalog input to Linux `legacy-export` using
    `--data-dir` and `--revision-id`. Existing seed-derived or wrapped database
    keys locate saved revision rows, legacy/scoped recovery heads or certified
    checkpoint history. Bounded SQL reads reject oversized records before payload
    allocation. Available recovered Inline sources and authenticated cached shards
    supply ciphertext without reading anchors, replaying journals, migrating
    schemas, wrapping keys, updating hints or retiring source records. File and
    catalog input modes are exclusive. Missing/invalid inputs fail before target
    publication. This does not inventory all retained history or recover absent
    sectors; peer/packed reconstruction and retained-history conversion remain
    open. Explicit original-anchor reads are implemented below.
    Validation: two new catalog fixtures cover legacy/wrapped keys, legacy/scoped
    recovery heads, certified history, mixed Inline/cache sources, unchanged
    database/key/journal bytes, preserved schema and failure without publication.
    Two store fixtures reject oversized records/keys and damaged recovery rows
    before visiting/allocating payloads. The actual offline CLI fixture covers
    both input modes and incomplete catalog arguments. All 104 core, 103 ordinary
    store, 87 ordinary Git, 370 ordinary Node and 26 CLI unit tests pass, plus the
    real export CLI fixture and eight provisioned snapshot regressions (699 unique
    cases). Disposable Btrfs mount/image/loop cleanup, formatting and strict locked
    workspace/all-targets Clippy pass. The 18 store, 62 Git and other 12 Node
    provisioned cases were not run by this slice; full M6 release gates remain open.
  - [x] Read explicitly supplied preserved anchor areas during catalog export.
    Linux `legacy-export --anchor-area PATH` pins each marked area, rejecting
    symlinks, special files, FUSE filesystems and nested mount crossings. It
    preserves marker/payload access times with mandatory no-atime reads and has
    no discovery, migration, journal replay, source-hint update or retirement.
    Historical AnchorFile/StableAnchorFile recipes keep their serialized tags;
    recorded IDs/raw relative paths resolve within selected areas, ignoring old
    path/volume/filesystem hints so relocated copies can be exported. Bounded
    ranges must reproduce the signed ciphertext roots/commitments before output
    publication. The destination parent must be outside the installation and all
    selected areas. Missing permission/ranges, offset overflow or changed bytes
    fail while preserving the original installation. Peer/packed reconstruction,
    retained-history inventory/conversion and full upgrade/recovery gates remain
    open; explicit area extraction alone does not qualify replacement protection.
    Validation: formats 6/7 export relocated historical AnchorFile and raw-path
    StableAnchorFile sources with exact signed bytes and unchanged marker/payload
    inode, length and atime/mtime/ctime. Two store fixtures cover pinned-area
    rename/replacement, symlinks, invalid markers, traversal and special files.
    The real CLI fixture exports a preserved anchor without the old view path.
    Range and parser fixtures reject overflow/short reads and incomplete/mixed
    inputs before recovery input. All 105 ordinary store tests, eight targeted
    Node export/range tests, four CLI unit tests and one real CLI fixture pass.
    Disposable Btrfs qualification passes eight snapshot regressions and the
    new nested-mount reader rejection, with verified mount/image/loop cleanup.
    Formatting and strict locked workspace/all-targets Clippy pass. The shared
    area-marker reader also caps the actual read against concurrent growth.
    This increment does not rerun the complete ordinary Node/Git suites,
    remaining 18 store/12 Node provisioned cases, or full M6 release qualification.
  - [ ] Finish the verified mount-free export/recovery policy, including
    unavailable historical metadata, and qualify legacy upgrade/recovery.
    Rejection and runtime removal do not certify historical conversion.

- [ ] **R2 / P1 — Make Git mutation and backup use one enforceable size budget.**
  Historical `crates/mb-git/src/history.rs` admission allowed up to 64 MiB of
  graph metadata, while `GitBackupDescriptor::validate` caps the full encoded
  descriptor at `V1_MAX_CATALOG_BYTES` (32 MiB), including refs, object records,
  blob sector references and serialization overhead. Current growing commands
  now preflight the complete dense Git descriptor against that bound, and native
  history has a status/export remedy. Full enclosing native/private and signed
  revision budgets still lack a shared mutation admission contract: an accepted
  Git descriptor alone does not prove a protectable revision. Define one versioned
  budget covering the full reachable descriptor and its enclosing revision metadata. Preflight commands
  that can grow it, including commits, refs/pins, merge, and import/fetch, before
  publishing catalog mutations; backup and recovery must enforce that same
  contract. Preserve existing oversized local history and give a precise status
  and migration/export remedy rather than trimming or claiming it is protected.
  Coordinate with R3 if the descriptor is split into authenticated pages; simply
  setting both constants to the same number does not account for overhead.
  Acceptance: just-below/at/above-budget histories, large refs/trees and blob
  geometry, import, and crash/reopen show every accepted protectable graph can
  produce a signed backup descriptor and recover exact refs, IDs, and bytes.
  Rejected mutations preserve the prior catalog and anchors.
  - [x] Bound canonical encoding before allocation and capture signing.
    Shared Postcard counting includes nested records, vector lengths and wire
    overhead, stops at the caller's exact inclusive limit and allocates only
    the counted output size. Git descriptor validation now checks the full
    32 MiB encoding without constructing a second descriptor buffer. Capture
    applies bounded checks to the anchor manifest and complete native/Git
    private metadata, and counts the enclosing revision with both fixed-size
    signatures before signing. The native legacy adapter uses the same counter.
    New fixtures cover exact encoding boundaries, early termination, preserved
    errors, a changing serializer, a valid Git graph below/at/above 32 MiB,
    native/Git envelope overhead and both signatures. Native Git capture/restore
    and rejected-capture repair pass on disposable Btrfs with verified cleanup.
    All 96 core and 73 ordinary Git tests, 28 ordinary snapshot regressions and
    six legacy adapter tests pass, with formatting and strict workspace/all-targets
    Clippy (62 Git and eight snapshot provisioned tests remain ignored in the
    ordinary suites; the two named Btrfs capture tests were run separately).
    Mutation preflights, the shared admission contract, oversized-history status
    and the complete R2 boundary/reopen/recovery qualification remain open.
  - [x] Preflight local commit, branch, pin and tag descriptor growth under the
    SQLite writer lock. The proposed complete reachable graph includes retained
    ancestry and all existing refs, plus the candidate records. A virtual dense
    recipe serializer counts exact current-format blob sector geometry without
    allocating sector vectors or rereading retained payloads. Oversized changes
    fail before their metadata/ref writes; annotated tag object/ref publication
    is now atomic. Cached lengths are admission geometry; backup/export still
    verify actual anchors. Existing history and staged anchors are preserved.
    Guarded publication rejects competing writers and rolls back SQL abort/ignore
    faults, including ignored deletion. Full enclosing native/revision budgets,
    merge/checkout/import/fetch preflights, oversized-history status and bounded
    incremental scheduling remain required; this descriptor check does not close R2.
    Validation: six targeted preflight/transaction fixtures, all 93 ordinary store
    and 77 ordinary Git tests, 28 ordinary snapshot regressions, all 62 provisioned
    Git library tests and both native Git capture/restore and rejected-capture
    repair pass. Disposable Btrfs mount/image/loop cleanup is verified. Formatting
    and strict workspace/all-targets Clippy pass. Ordinary suites retain 18 ignored
    store cases and eight ignored snapshot cases; this is not a full M6 release gate.
  - [x] Preflight fetch and stock branch/tag push against the combined destination
    graph before recording a new intent or capturing blobs. Imported lengths
    permit exact dense recipe counting before anchors exist and must agree with
    existing cached mappings. Replayed intents recheck admission before import;
    capacity rejection retains the exact intent and prior history for repair.
    Final publication rechecks the budget, intent, tag namespace, expected ref,
    branch selection and fast-forward condition under the writer lock. Push
    metadata, refs and temporary intent retirement now commit together. Ancestry
    checks use proposed objects in a temporary repository without durable writes.
    Fresh rejected imports create no intent or anchors. Previously captured
    pending anchors remain owned if a later capacity check fails. Signed backup
    reconstruction, merge/checkout, full enclosing budgets and oversized-history
    status/export qualification remain open; this does not close R2.
    Validation: two new fixtures reject individually bounded histories whose
    combined descriptor cannot fit, preserve oversized pending intents on reopen,
    import reused anchors, publish a valid fast-forward and reject divergence
    before metadata writes. All 79 ordinary and 62 provisioned Git library tests,
    28 ordinary snapshot regressions and both native capture regressions pass,
    with verified disposable Btrfs cleanup, formatting and strict workspace/
    all-targets Clippy. Eight provisioned snapshot cases remain ignored in the
    ordinary suite; the two named capture cases ran separately.
  - [x] Preflight generated merges and checkout descriptor growth. Merge builds
    its bounded generated blobs in a disposable memory backend, checks the whole
    candidate graph before capturing anchors, then rechecks branch/HEAD and size
    under the metadata publication writer lock. Branch-switch sizing includes
    the prospective primary HEAD name; linked HEADs remain independent. Fresh
    checkout checks admission before persisting an intent; replay checks before
    staging/moving files. Final index/HEAD/ref publication and merge-session
    retirement recheck intent ownership, branch/target and size atomically.
    Same-tree branch selection uses the same writer-locked budget. Restore
    operations and already-published cleanup do not acquire a growth restriction.
    Rejected fresh merges preserve existing anchors and history; a rejected
    pending checkout preserves its immutable journal for repair. Later failures
    after successful initial admission can retain captured pending anchors or
    partially applied worktrees under their existing replay journals.
    Four new fixtures cover proposed HEAD validation, generated merge rejection
    before anchor capture, HEAD-name growth at the descriptor boundary, and
    oversized checkout replay without staging, including preserved history on
    reopen. Full enclosing native/revision budgets, signed backup reconstruction,
    oversized-history status/export and incremental scheduling remain open;
    this descriptor admission increment does not close R2 or enable 1 TiB support.
    Validation: all 83 ordinary and 62 provisioned Git library tests, 28 ordinary
    snapshot regressions and both native Git capture/restore and rejected-capture
    repair pass, with verified disposable Btrfs mount/image/loop cleanup. Formatting
    and strict workspace/all-targets Clippy pass. The targeted admission run also
    passes both existing SQL writer/fault fixtures. Eight provisioned snapshot
    cases remain ignored in the ordinary suite; the two named native capture
    cases ran separately. This is not the complete M6 release gate.
  - [x] Guard backup graph reconstruction against competing catalog writes.
    Import validates the descriptor's real encoded sparse recipes and exact native
    blob IDs before preparing metadata, then rechecks an empty metadata/ref/index/
    HEAD destination and any anchor-record conflicts under its publication writer
    lock. Object mappings, metadata, refs and clean index/HEAD publish together;
    competing state remains intact. Recovery keeps the descriptor's original
    recipe geometry rather than applying a prospective dense mutation estimate.
    Two new fixtures inject competing writes in each destination namespace and
    anchor mapping, preserve them across reopen, then recover exact refs, IDs,
    index and anchor bytes after repair. Real libgit2-valid descriptors immediately
    below, at and above 32 MiB prove accepted imports reopen exactly and rejected
    imports leave the catalog empty. Caller authentication of enclosing signed
    revisions remains required; these fixtures do not claim end-to-end capacity
    qualification or complete the shared enclosing R2 budget.
    Validation: all 85 ordinary Git library tests and 28 ordinary snapshot
    regressions pass, as do provisioned annotated-tag backup import/reopen and
    both native capture regressions on disposable Btrfs, with verified mount/
    image/loop cleanup. Formatting and strict workspace/all-targets Clippy pass.
    The ordinary suites retain 62 provisioned Git and eight snapshot cases;
    the one Git import case and two capture cases were run separately here.
  - [x] Report current descriptor capacity and preserve oversized native history
    through full stock Git export. Primary and linked status share a read-only
    current-capture measurement of all reachable refs, ancestry and dense blob
    recipes, bounded by the inclusive 32 MiB descriptor limit. Unavailable graph/
    mapping results remain unverified; fitting the descriptor does not attest the
    enclosing revision or remote protection. An optional local-control field
    preserves decoding of older status responses. `mutualgit status` reports the
    failed limit and an export command. `mutualgit export EMPTY_BARE_REPOSITORY`
    preserves every retained ref, exact blobs/metadata and primary symbolic HEAD,
    including remote-tracking refs and pins, without the descriptor size gate.
    It rejects populated destinations and paths inside primary/linked roots,
    locks destination refs, verifies payloads and leaves source history intact.
    External ref publication may fail partway; retry into a fresh empty target
    while retaining the source. Existing graph traversal bounds still apply.
    This native export does not qualify withdrawn FUSE history conversion or
    production paged migration. Full enclosing R2 budgets and R3 remain open.
    Validation: all 87 ordinary and 62 provisioned Git library tests, 28 ordinary
    snapshot regressions, seven mutualgit unit tests and the expanded local-wire
    schema fixture pass. The real daemon/CLI raw-path fixture exports remote refs,
    tags, pins and non-UTF-8 paths with exact bytes and stock Git strict fsck.
    Both native capture regressions pass. Disposable Btrfs mount/image/loop cleanup,
    formatting and strict workspace/all-targets Clippy are verified. The ordinary
    snapshot suite retains eight provisioned cases; the two capture cases ran
    separately. These checks do not replace full M6 release qualification.

- [ ] **R3 / P1 — Replace the prototype snapshot-capacity ceiling with a defined
  production catalog design.** The first-release acceptance target is **1 TiB
  per protected dataset, including retained history**, selected by the user on
  2026-10-06. This is a required target, not current supported capacity.
  `crates/mb-node/src/snapshot.rs` permits 39,488
  data-sector references at 64 KiB each: about 2.41 GiB of represented sector
  data, with sparse extents, shared inodes, and per-file rounding affecting
  effective capacity. This is a deliberate current bound, not evidence of
  corruption, but it is too small for general-purpose production backup. Define
  supported dataset/file/history limits and replace flat per-revision metadata
  with bounded, authenticated, versioned catalog pages or another explicit
  scalable design. Bound each page/frame, traversal memory, and incremental
  capture work; cover signing, packing, replay, retention, and recovery together.
  Preserve old catalog decode and define migration; do not just raise constants
  and move the failure into another parser or allocation. Until migration is
  implemented, validate and report the existing limit before claiming protection.
  Acceptance: dense files, sparse extents, hard-link sharing, many small files,
  retained Git history, and datasets above the old ceiling meet the declared
  limits with bounded memory; interrupted backup, prune, and seed-only recovery
  preserve exact data and old supported revisions remain readable.

  - [x] Add the authenticated page foundation in `mb-core` and record the
    implementation direction in
    [`docs/adr/0002-production-catalogs.md`](docs/adr/0002-production-catalogs.md).
    The format binds dataset or guild scope and section, encoded page bytes,
    child order, decreasing height, subtree bytes and page occurrences.
    Construction and traversal retain bounded buffers; oversized collection
    declarations are rejected before allocation. Storage/fetch failure prevents
    continuation or an emitted root. Eight targeted corruption, scope,
    ordering, count, geometry, boundary and failure cases pass, along with all
    58 core tests, formatting and strict workspace/all-targets Clippy. The
    structural 16 GiB metadata-bound fixture is not a 1 TiB data qualification.
    Existing signed revision/checkpoint formats and runtime limits remain in
    force until their consumers migrate.
  - [x] Persist local page ownership in the existing SQLCipher control schema.
    Child-first staging verifies immutable pages and immediate children before
    atomically recording pins and parent links. Root publication is fenced by
    the durable intent; cancellation blocks stale writes before cleanup.
    Surplus pins and unreferenced pages are released one at a time, preserving
    shared and pending successor closures. SQL reads bound payload/key
    allocation before materialization. Four interruption/reopen, sharing,
    corruption and transaction-failure fixtures pass; all 58 core and 79
    ordinary store tests pass (18 provisioned store tests remain ignored),
    along with formatting and strict workspace/all-targets Clippy. This is
    local catalog ownership, not signed revision or remote protection.
  - [x] Add context-bound public/private page address and encryption primitives.
    Private file/Git page IDs are keyed and derivable from an authenticated
    parent reference, scope and section without fetching the child's plaintext.
    Public source and guild catalogs use a separate address domain. Sealing
    verifies the page first; opening checks the expected address, exact sector
    geometry and ciphertext root, zero padding, plaintext hash and canonical
    page. Seven crypto fixtures cover domain/test-vector stability, keys,
    scope, geometry, corruption, seed-derived tree traversal and reconstruction
    of missing encrypted information pages with exact roots/commitments.
    All 19 catalog tests and all 65 core tests pass, along with formatting and
    strict workspace/all-targets Clippy. Protocol authorization and integration
    with signed revision/source roots remain in the consumer migration gate.
  - [x] Add bounded version-one record framing over authenticated pages.
    Serialization uses a fixed 48 KiB buffer; traversal returns one bounded
    frame and rejects malformed lengths, truncation, excess records and trailing
    bytes. Frames may cross leaf boundaries. Storage/fetch failures fence
    continuation and publication. Five new framing fixtures, all 24 catalog
    tests and all 70 core tests pass, with formatting and strict
    workspace/all-targets Clippy. Schema-specific nested collection bounds,
    typed records and runtime consumers remain open; framing alone does not
    enable production capacity.
  - [x] Add typed source-sector records and streaming validation. Fixed-size
    records pair the exact sector reference with its Merkle commitment; decoding
    checks canonical encoding, version and encrypted-sector geometry. Strict
    sector-ID order rejects duplicates and conflicts with constant memory.
    The authenticated root accounts for unique-source logical bytes, checked
    before yielding the final source. Five new fixtures and all 29 catalog
    tests and 75 core tests pass, with formatting and strict
    workspace/all-targets Clippy. This does not establish physical quota or
    retained dataset capacity; signed revision/packing consumers still need
    migration.
  - [x] Add bounded Git metadata-object fragments. Commit/tree/tag headers
    and fixed 32 KiB fragments stream in OID order; readers check canonical
    encoding, fragment declarations before allocation, offsets, lengths,
    incremental Git OIDs and final object/count/byte summaries. Input, hashing,
    storage and fetch failure fence continuation/publication. Six fixtures
    include a generated object above the old 32 MiB descriptor bound, independently
    hashed and regenerated using libgit2's native streams. All 55 ordinary Git
    tests pass (62 provisioned tests remain ignored), with formatting and strict
    workspace/all-targets Clippy. This is object-codec qualification, not an
    above-limit graph backup; full DAG/ref/blob validation, legacy migration
    and end-to-end admission/recovery remain open.
  - [x] Add bounded sparse Git blob recipes and a legacy recipe adapter.
    Blob/extent headers declare exact counts; fragments contain at most 128
    sector references, preserving repeated references and their order. Readers
    reject overlap, overflow, incomplete coverage, count/order/schema errors
    and incorrect final summaries before yielding the final record. Nested
    declarations reject before allocation; failures fence publication and
    continuation. Six fixtures cover exact legacy conversion across pages,
    empty/all-hole blobs, geometry, malformed encoding, summary substitution,
    interruption and overflow. All 61 ordinary Git tests pass (62 provisioned
    tests remain ignored), with formatting and strict workspace/all-targets
    Clippy. The synthetic 1 TiB sparse layout is codec qualification only.
    Source-authority joins, plaintext blob hashing and runtime migration remain
    required before accepting a paged descriptor as protected/recoverable.
  - [x] Add bounded Git refs and the complete paged Git root/legacy adapter.
    Component ordering catches parent/child namespace conflicts with one prior
    name, including conflicts hidden by ordinary byte sorting. Ref names are
    bounded to 8 KiB, selected branch names to 1 KiB; selected/unborn HEAD is
    authenticated and checked before the final ref is returned. The 4 KiB
    enclosing root applies one aggregate metadata/page-occurrence bound across
    refs, objects and recipes. Supported legacy graphs validate before writes
    and preserve exact refs, object bytes/IDs, recipes and branch selection;
    failed conversion leaves their signed bytes unchanged. Five ref and four
    combined-root fixtures pass, including staged control-store reopen. All
    50 catalog and 70 ordinary Git tests pass (62 provisioned Git tests remain
    ignored), with formatting and strict workspace/all-targets Clippy. Durable
    multi-root/signed publication, source joins, bounded DAG validation and
    capture/recovery/admission integration remain open; this does not close R2.
  - [x] Add atomic local multi-root publication and cancellation. A bounded
    descriptor bundle publishes up to 16 existing intents/root pins and at most
    4 KiB of descriptor bytes in one SQLCipher transaction. Immutable retries
    bind every byte; intent-to-bundle links block independent member cancellation.
    Group cancellation fences every member before cleanup, preserving shared
    pending/published successors. SQL bounds the journal payload before
    materialization, and nested declarations reject before allocation. Intent
    updates now check affected-row counts so an ignored SQL update cannot
    falsely succeed. Four new bundle fixtures include reopen at publication,
    pin-release/cancellation/GC boundaries, sharing, corruption and injected
    abort/ignore failures. All 54 catalog and 83 ordinary store tests pass
    (18 provisioned store tests remain ignored), with formatting and strict
    workspace/all-targets Clippy. Typed Git publication wiring, signed revision
    authority, physical quota and authenticated generation-floor retirement
    remain open.
  - [x] Wire typed Git roots to durable bundle publication. An explicit
    ref/object/blob stream selector stages each stream under a separate intent;
    the existing single-sink adapter stays compatible. Typed publication binds
    precisely those three roots to the canonical descriptor. Reopen verifies
    dataset scope, repository identity, role order and exact root references
    against the bundle before exposing the descriptor. The former staging-only
    fixture now exercises atomic publication, pin release, exact metadata/recipe
    recovery and cancellation/GC. Two additional fixtures reject mismatched
    ownership and demonstrate interruption without publication plus fenced
    retry/cleanup. All 56 catalog and 72 ordinary Git tests pass (62 provisioned
    Git tests remain ignored), with formatting and strict workspace/all-targets
    Clippy. Daemon capture, signed activation, source-authority joins and seed-only
    recovery still need consumer migration; local publication does not close R2/R3.
  - [x] Add bounded native file namespace and attribute records. Raw paths are
    bounded to 8 KiB; component ordering validates declared directory parents,
    duplicates and file/alias children with two bounded path buffers. Records
    preserve root/directory/file attributes and hard-link group IDs; file keys
    equal their record ordinal. Checked counts and file/alias byte totals are
    verified before returning the final record; encoding, storage and fetch
    failures fence continuation/publication. Six fixtures include multi-page
    raw-path round trips and an independent comparison over all 19,683 nested
    absent/directory/file assignments. All 81 core tests and the workspace
    catalog-filtered suite pass, with formatting and strict all-target Clippy.
    This codec covers namespace/attributes; bounded sparse recipes, link/source
    joins, legacy conversion and runtime capture/restore migration remain open.
    Complete platform metadata and real 1 TiB qualification remain required.
  - [x] Add bounded sparse native file recipes and a borrowed legacy extent
    bridge. File keys preserve namespace record ordinals; extent/sector counts,
    offsets, coverage and fragment order are checked with current-file counters.
    Fragments contain at most 128 references and retain repeated sectors exactly.
    Empty/all-hole files remain explicit. Root totals are verified before the
    final record is yielded; failures fence publication/continuation. The bridge
    counts and emits borrowed extents without another complete recipe vector.
    Five fixtures and all 86 core tests pass; the catalog-filtered workspace
    suite passes 84 tests with two provisioned tests ignored. Formatting and
    strict workspace/all-targets Clippy pass. Sparse logical lengths in these
    fixtures do not qualify real payload or retained-history capacity.
  - [x] Bind native namespace and recipe roots and join exact file keys/lengths.
    A canonical container of at most 1 KiB shares one aggregate metadata/page
    budget across both trees. The joined reader retains one pending header and
    interleaves each entry with its bounded recipe fragments. Missing, extra,
    incomplete or substituted recipes reject, even when total counts/bytes
    match. Both EOFs are verified before the final combined event is returned;
    failures fence continuation. Seven fixtures exercise all entry endings,
    substitutions, corruption, interruption, aggregate bounds and both trees'
    page boundaries. All 93 core tests and 91 catalog-filtered workspace tests
    pass (two provisioned tests remain ignored), with formatting and strict
    workspace/all-targets Clippy.
  - [x] Derive disk-backed native hard-link/source joins from verified streams.
    A scoped manifest binds the native and source roots under one aggregate
    metadata/page budget. Indexed SQL rows check exact recipe sector references
    without a dataset-sized memory map. Group attributes and domain-separated
    recipe hashes preserve duplicate primaries and resolve forward aliases;
    every alias requires a primary. Lookup rows and completion commit atomically
    after all authenticated EOFs/joins; failures roll back, immutable retries
    bind the same manifest, and cancellation fences lookup/retry before bounded
    cleanup. Five fixtures cover 3,200 multi-page sources/groups, repeated sectors,
    reopen/cleanup, conflicts, cached-row bounds and SQL abort/ignore injection.
    The catalog-filtered workspace suite passes 96 tests with two provisioned
    tests ignored; all 88 ordinary store tests pass (18 provisioned store tests
    remain ignored), with formatting and strict workspace/all-targets Clippy.
    This is local metadata validation; caller authentication,
    ciphertext verification, root ownership, typed publication and runtime
    scheduling/activation remain required. Validation currently scans complete
    streams in one writer transaction; incremental update scheduling remains open.
  - [x] Publish validated native catalogs with exact typed root ownership.
    Namespace, recipe and source intents bind to the immutable validation
    manifest in one publication transaction. Typed reopen checks scope,
    descriptor, ordered roles/roots and consistent validation/member/link
    states. Independent index/bundle/member cancellation is rejected while
    published; typed cancellation fences the index and all roots together
    before bounded cleanup. Three new fixtures cover reopen, every cleanup
    boundary, scope/role/ownership substitution and injected SQL abort/ignore
    rollback. All 91 ordinary store and 72 ordinary Git tests pass (18 store
    and 62 Git provisioned tests remain ignored), with formatting and strict
    workspace/all-targets Clippy. Local publication does not establish signed
    activation, ciphertext protection, runtime support or production capacity.
  - [x] Add a borrowed converter for supported legacy native entries.
    Decoded formats 1–5 preserve attributes, dense/sparse recipes, repeated
    sectors and hard-link identities without rewriting original signed bytes.
    Format 4/5 Git descriptors are preserved and converted separately. A bounded
    32 MiB encoding counter and dry conversion reject invalid versions, paths,
    recipes and original-order hard links before external page writes. The
    adapter emits explicit namespace/recipe roles and requires authenticated
    source joins before typed publication. Six adapter tests and 26 snapshot
    regressions pass (eight provisioned snapshot tests remain ignored), including
    both immutable version-2 fixtures and decoded version-4/5 Git envelopes,
    with formatting and strict workspace/all-targets Clippy. Unsupported legacy
    shapes retain their existing recovery path; this does not activate a new
    format or complete historical migration.
  - [x] Connect private catalog pages to live local-sector regeneration with
    durable recipe ownership. A new append-only source variant references one
    authenticated page instead of embedding its plaintext in an Inline recipe.
    The Node staging API verifies owner, scope, section and page, derives the
    private sector address, ciphertext root and Merkle commitment, and publishes
    its bounded recipe with a dedicated page-root pin in one writer transaction.
    Active recipe pins cannot be cancelled independently or attached to descriptor
    bundles. They retain shared descendants after the original builder is
    cancelled. An indexed cursor visits one source pin per cleanup step; deletion
    or replacement of its exact source record permits atomic fencing and release.
    Checkpoint cleanup performs one such visit and one bounded page-GC step.
    Existing source variants keep their discriminants and render unchanged.
    Rendering now rejects a mismatched recipe key or oversized logical length
    before reading/allocating file payloads. Five new fixtures cover shared-page
    closure, reopen, per-step cursor work, SQL ignore rollback, exact live Node
    rendering, owner/guild/reference/page substitution and legacy Inline bytes.
    This is a live source adapter, not a signed paged revision or production
    capture/packing/retention/seed-recovery migration. Current revision/private
    metadata formats and limits remain; withdrawn private versions 6/7 are not
    reinterpreted. Full R2/R3 admission and 1 TiB qualification remain open.
    Validation: all 96 core, 96 ordinary store, 87 ordinary Git, 362 ordinary
    Node and 16 CLI-library tests pass. All 62 provisioned Git and all eight
    provisioned snapshot regressions pass on disposable Btrfs, with verified
    mount/image/loop cleanup. Formatting and strict workspace/all-targets Clippy
    pass. Ordinary suites retain 18 store, 62 Git and 20 Node provisioned cases;
    the Git and snapshot cases above ran separately. This is source integration
    and legacy regression qualification, not the complete M6 production gate.
  - [x] Add authenticated byte-range traversal with bounded seek work.
    `CatalogRangeReader` verifies each intersecting parent and leaf, uses
    authenticated child lengths to skip unrelated subtrees, and returns only
    the requested bytes in bounded chunks. Repeated page occurrences retain
    their distinct stream offsets. Storage/verification failures poison the
    reader; invalid and overflowing ranges fail before fetching. Empty ranges
    perform no fetch. This is range authentication, not full-catalog validation.
    Three core fixtures cover boundary combinations, partial leaves, corruption,
    scope/reference substitution, storage failures and small reads at the exact
    16 GiB catalog-stream limit. One reopened SQLCipher fixture proves a tail
    read fetches only its root and leaf despite an unrelated corrupt leaf;
    whole-stream traversal still detects that corruption. The maximum-size
    fixture uses repeated authenticated subtrees, not real 1 TiB dataset data.
    Production consumer migration, variable-length edits and stable record
    locations remain open; this does not change current snapshot limits.
    Validation: all 99 core and 97 ordinary store tests pass (18 provisioned
    store cases remain ignored), with formatting and strict workspace/all-targets
    Clippy. No native source-backend or topology behavior changed in this step.
  - [x] Add bounded path-copying byte splices and durable successor staging.
    `CatalogPageRef::splice` inserts, deletes or replaces a byte range with at
    most 60 KiB of replacement bytes, fetching only boundary paths and reusing
    untouched subtree addresses. It skips fully deleted subtrees and emits new
    pages child first. Repeated page occurrences remain independent by offset;
    unchanged pages produce no sink writes. Root splits preserve page bounds;
    edits exceeding stream or height geometry fail without returning a root.
    `ControlStore::stage_catalog_splice` stages a successor under a Building
    intent, including root ownership for no-op edits. Publication stays explicit;
    failed edits leave durable pending pages for retry or cancellation while
    the original root remains pinned. Five core fixtures cover insertion,
    deletion, replacement, boundary combinations, parent splitting, repeated
    occurrences, no-ops, corruption/fetch/sink failures and geometry rejection.
    Small edits and nearly complete deletion at the exact 16 GiB catalog-stream
    bound use at most two boundary paths, using repeated authenticated subtrees
    rather than real dataset data. Two SQLCipher fixtures cover staged/published/
    cancelled reopen, shared-closure reclamation and retry after an injected
    parent-insert failure with leaves already durable. Typed-record indexing,
    multi-edit scheduling, general tree rebalancing/compaction, quota admission
    and production capture/recovery integration remain open. This does not
    change current snapshot limits or qualify the 1 TiB release target.
    Validation: all 104 core and 99 ordinary store tests pass (18 provisioned
    store cases remain ignored), with formatting and strict workspace/all-targets
    Clippy. Native source-backend and topology gates were not rerun for this API.
  - [x] Repair damaged private catalog page payloads through the live recovered
    information-sector installer. A bounded active source descriptor ties the
    page to its exact local recipe and published pin. Node verifies the recovered
    sector reference, guild/owner/scope, private address, ciphertext root,
    canonical padding and page before repair. One writer transaction rechecks
    recipe ownership, immutable page metadata and immediate child links, then
    restores only the payload. A parent can be repaired while a child's payload
    is missing; each child remains independently authenticated and repaired.
    No Inline conversion or pin retirement occurs for an active page source.
    Replacement/deletion of the recipe and retired intents fence stale repairs;
    SQL IGNORE faults are rejected by affected-row checks. Two store and two
    live Node fixtures cover corruption, missing payloads, reopen, stale recipe
    snapshots, SQL ignore, retirement, independent parent/child repair and
    guild/reference/ciphertext substitution, preserving recipe bytes, sector
    ciphertext and commitments. This repairs existing local page ownership;
    seed-only reconstruction of absent descriptors/ownership, signed paged
    revision authority and production capture/recovery migration remain open.
    Validation: all 104 core, 101 ordinary store, 364 ordinary Node and 16
    CLI-library tests pass, plus all eight provisioned snapshot regressions on
    disposable Btrfs with verified mount/image/loop cleanup. Formatting and
    strict workspace/all-targets Clippy pass. Ordinary suites retain 18 store
    and 20 Node provisioned cases; the eight snapshot cases ran separately.
    This does not qualify complete seed-only paged recovery or the M6 topology.
  - [ ] Implement complete legacy private metadata conversion and migrate
    native capture/restore consumers before enabling the new format.
  - [ ] Add quota reservations, bounded packing/coding record
    codecs and incremental seek/edit operations. Retire intent tombstones only
    behind a verified generation floor. Qualify interruption/reopen,
    cancellation and small changes to large catalogs.
  - [ ] Migrate revision/Git admission, packing, coding/checkpoint replay,
    retention and seed-only recovery together; qualify the declared capacity
    and geometry policy on real data before enabling production admission.

- [x] **R4 / P1 — Complete variable-profile disk evacuation.**
  Implemented bounded READY enumeration and durable local transfers for variable
  information/parity shards alongside legacy objects. Destination writes count
  reservations and headroom, preserve attempt/receipt/verification evidence,
  and verify exact bytes before publishing the location. The source remains
  readable until the destination is READY; conditional source cleanup and
  transfer retirement replay after reopen. Authoritative repair copies retain
  their own evidence. GC and abort durably cancel unfinished transfers and keep
  offline copies owned until cleanup; successor attempts remain intact.
  In-flight uploads can finish on a draining source or abort. STAGED objects,
  physical reservations, and control-only coding/retirement obligations block
  final retirement. Each source's retirement is persisted before the next
  source can fail. Qualification is recorded below; broader release-artifact
  and platform validation remains R7.

  - [x] Repair interrupted coding-upload reservation retirement. A retry after
    receipt publication now verifies the physical STAGED/READY shard and the
    pending reservation identity before conditionally retiring the control
    reservation. Missing, offline, or conflicting storage preserves the control
    evidence. Crash/reopen and READY replay fixtures pass; the volume suite
    passes 39 ordinary tests (one privileged test remains ignored). The packed
    partial-upload network retry/reopen fixture passes, as do formatting and
    strict workspace/all-targets Clippy. This fixes a pending-ownership replay
    boundary separately from the transfer integration below.

  - [x] Add the verified READY transfer primitives. The store enumerates one
    variable shard in a consistent snapshot, carrying its original attempt,
    staged receipt, and verification hash. Atomic copying verifies the payload
    and evidence and counts coding reservations against destination capacity;
    conditional source deletion rejects different attempt/root/verification
    evidence. Three targeted corruption, pending-ownership, capacity, replay,
    and reopen fixtures pass, along with all 51 database tests, formatting, and
    strict workspace/all-targets Clippy. Transfer publication and evacuation
    are qualified separately below.

  - [x] Integrate and qualify cross-volume evacuation. Fifteen new volume
    fixtures cover information and parity, all five transfer publication
    boundaries plus source retirement, full/offline destinations, logical and
    physical headroom, malformed/corrupt evidence, reused repairs, successor
    protection, pending upload completion/abort, control-only reservations,
    mixed formats, and GC/abort interleavings including interrupted GC and
    offline cleanup. The complete volume suite passes 54 ordinary tests; its
    remaining privileged headroom fixture also passes on disposable Btrfs,
    with mount/image/loop cleanup verified. The Node detach fixture passes
    live-reader access, missing-shard reconstruction, exact bytes after reopen,
    and rejection of another guild. Existing full coding activation/replay and
    packed partial-upload network retry/reopen fixtures pass. Formatting and
    strict workspace/all-targets Clippy pass. The locked workspace binary build
    and CLI/daemon executable smoke checks pass.
    The complete locked workspace run on committed `28cae0e` also passes:
    637 passed, zero failed, 105 ignored. The privileged volume headroom case
    among those ignored tests was separately provisioned and passed above.

- [x] **R6 / P2 — Package ordinary Git as an explicit runtime dependency.**
  Implemented: the default Nix runtime wraps the CLI, daemon, native Git command,
  and remote helper with pinned ordinary Git on PATH; the optional alias points
  to that runtime. Standalone static lab artifacts and Cargo builds declare the
  daemon's ordinary-Git PATH requirement. Discovery preserves alias skipping and
  gives an actionable missing-dependency error. `scripts/packaged-git-smoke.py`
  checks packed import, both bridge directions, binary/CRLF bytes, commit IDs,
  and absence of a native Git payload mirror with an isolated PATH, both with
  and without the alias. A dedicated CI job runs this against installed Nix
  artifacts. Validation: the installed Nix runtime and alias passed all three
  smoke scenarios on disposable Btrfs, including a raw standalone missing-Git
  error before visible refs/history changed. Alias discovery/error tests and
  ordinary Git library tests pass; format and strict workspace Clippy pass with
  unrelated FUSE test WIP held aside and restored. The runtime closure contains
  pinned Git 2.55.0. This qualifies the Git dependency slice; broader release
  artifact and topology qualification remains R7.

- [ ] **R7 / P1 — Automate mandatory validation for the exact release artifact.**
  Nix `checks` currently point at build artifacts with `doCheck = false`;
  successful builds do not run the required ordinary or privileged suites.
  `.github/workflows/ci.yml` already runs format, strict Clippy, locked workspace
  tests, Docker safety, reflink/network acceptance, port-mapping, and private-Tor
  recovery. Preserve those jobs and keep the build-only Nix sandbox distinction.
  The new `native-git-acceptance` job invokes the complete
  `scripts/git-linux-acceptance.sh` gate on disposable Btrfs, retains the gate and
  per-peer logs before mount cleanup, and unmounts/removes its image on exit.
  Topology fixtures now optionally archive their named daemon logs before
  successful cleanup and during failure unwinding. Provisioned archive
  qualification is tracked below. Required
  upgrade/multi-volume regression coverage remains open. The dedicated packaged Git runtime
  smoke job now covers the R6 slice. Qualify
  the exact release artifact through native-filesystem, topology, and source-loss
  scenarios, rather than equating a build or source-tree test pass with packaged
  behavior. Run R1-R6 regressions on one recorded source and its release candidate.
  Port the generic Git-history retention, grace-window prune, remote coded-data
  reclamation, and repeated seed-recovery assertions currently embedded in
  guarded fixtures to the native backend before those fixtures are removed;
  prior FUSE test passes do not qualify the replacement. Preserve exact-byte
  Git interop and no-duplicate-payload checks. Bound test timeouts, retain
  per-peer diagnostics, and independently audit mount/image/loop/network cleanup.

  - [x] Port the five-peer format-7 checkpoint fixture to native Git capture and
    normal Git commands. Preserve exact CRLF/NUL blob OIDs and bytes, branches,
    tags and commit pins, checkpoint grace protection, physical history-anchor
    reclamation, expired raw/packed cache and READY shard deletion, and seed-only
    recovery after two complete owner losses. Both losses erase state, source,
    and external native anchor areas; the second also erases the stock-Git
    export. Recovered catalogs contain
    independent format-1 blob anchors, with no ordinary `.git` payload mirror;
    committed blobs and unstaged working bytes remain distinct. Remove the four
    guarded-only helpers left unused by this port. The fixture binds its private
    control socket in a separate short temporary path before peer setup, keeping
    long qualified filesystem paths within the Unix socket limit. The stock-Git
    bridge and five-daemon topology fixtures also use separate short private
    control paths, including both recovered peers.
    Validation: disposable Btrfs passes in the workspace feature configuration
    (727.04 seconds) and the acceptance script's node configuration (690.01 seconds).
    Format and strict all-target workspace Clippy pass with pre-existing FUSE
    test WIP held aside; that WIP is restored after each qualification run.
    The remaining native Git stages also pass: all 62 ignored Git library cases,
    extent sharing, daemon Git reopen/linked worktrees/signed-history prune,
    seed-only branch/blob recovery, backend migration, encrypted history/root
    restore, stock-Git fetch/push, and raw Unix CLI/daemon/Git paths. The gate was
    resumed after correcting the fixtures' socket length and directory privacy;
    unchanged stages were not rerun solely to produce one uninterrupted log.
    The provisioned five-daemon topology also passed (2,095.29 seconds),
    exercising source/storage loss, native Git recovery, direct and punched
    paths, relay fallback, and final verified backup. This run still logged
    transient four-of-five signatures and stale endpoint retries; R5 stays open.
    The runner verified mount/image cleanup and restored the pre-existing WIP
    byte-for-byte. Independent cleanup checks found no remaining test network
    namespaces, loop devices, or fixture firewall rules. Workflow syntax and the diagnostic log-copy
    step were checked locally; the hosted CI job has not been run here.

  - [x] Qualify topology log archival on the provisioned five-daemon scenario.
    Implemented: `MUTUALBACKUP_TEST_LOG_ROOT` selects a separate private artifact
    directory. Both process and private-Tor fixtures archive named daemon logs
    after stopping daemons and before successful cleanup, and on failure unwind.
    The collector copies only regular named daemon logs, refuses symlinks, and
    never walks protected source directories. A copy error preserves the fixture.
    CI retains these archives and also collects remaining logs after abrupt
    failures. All 15 ordinary process-acceptance tests pass, including successful
    cleanup, failure unwind, privacy/filtering, and copy-error preservation;
    workflow syntax, format, and strict workspace/all-target Clippy pass.
    The provisioned scenario passed on `b27b030` (1,817.77 seconds), including
    source/storage loss, direct and punched paths, relay fallback, and final
    verified backup. All eight named daemon logs survived fixture removal and
    disposable image cleanup with 0700 directories and 0600 files. Recorded
    source and binary hashes matched after the run; independent audits found no
    fixture namespace, loop, or firewall resources. Coordinator and recovered
    peer status snapshots are retained beside the logs. Transient four-of-five
    signatures occurred during recovery and transport replacement; this passing
    run does not resolve R5's original stall.

  Acceptance: a failing or omitted required job blocks release; every supported
  backend passes its native capture/edit/restore, crash, retention/prune, and
  source-loss matrix on the release source. Record repeated topology evidence
  for R5 rather than interpreting one rerun as a reliability fix.

- [ ] **M6 finish the versioned native source-backend boundary across platforms.**
  Keep Linux reflink capture records and Git catalog backend binding, and finish
  the planned Windows NTFS/VSS and macOS clone backends, portable metadata and
  watcher behavior, and application-consistent capture hooks. Each supported
  platform requires local capture/edit/restore, source-loss recovery, and raw
  Git add/checkout/interoperability acceptance. Passing Linux probes do not
  qualify another platform. Keep signed peer formats independent of the local
  backend; reject unsupported capture instead of making an unannounced full
  copy. Older unbound reflink catalogs may migrate to `ReflinkV1` under the
  existing verified rules; existing guarded catalogs follow R1's explicit
  legacy/export policy. Retain the normal catalog reopen/mismatch regressions.
  Any narrower first release must explicitly defer additional platforms in its
  support matrix, not silently mark their gates completed.

- [ ] **R5 / P1 — Resolve the existing M6 topology/signature liveness gate.**
  The original provisioned backup stall after relay-only storage recovery remains
  open. Trace the exact missing signer, durable signature lock/event hash,
  authoritative endpoint generation, connection/circuit state, and retry progress
  together; distinguish an offline/quorum-blocked operation from a live but
  stalled retry. Correct the demonstrated cause without weakening signatures or
  declaring backup success prematurely. Acceptance: deterministic coverage of
  the diagnosed path plus repeated provisioned endpoint-replacement, relay-only
  recovery, partitions, and interrupted-retry runs on the exact release source
  either commit verified protection or expose an actionable blocked state with
  durable retry. Keep the historical evidence below; later successes do not
  explain the original 5,400-second outlier.

  Existing investigation and validation record:

  Added correlated event diagnostics to signature failures and dissemination:
  guild/sequence/event hash, signer, partial signature count, and coding
  group/attempt identity. Rejected transition admission reports the requested
  hash and verified local proposal-lock hash or lock validation error. Durable
  lock creation/reuse/conflicts and partial-signature persistence identify the
  same event, including the remaining signer set at debug level. Strict
  workspace/all-targets Clippy passes; the reopen/signature-isolation,
  majority-with-slow-minority, bounded dissemination, and unrecovered-member
  admission fixtures pass. This improves future diagnosis; connection/endpoint
  correlation and reproduction of the original stall remain open.

  The 2026-10-06 withdrawal-audit workspace run, overlapping native artifact
  compilation, failed `mixed_packed_group_replacement_reclaims_obsolete_ready_shards`
  with fewer than two reachable coding coordinators and
  `packed_failure_retry_restages_remote_inputs_after_partial_upload_and_reopen`
  because the persisted group transcript named a different attempt from the
  retry's activated plan. Both passed individually (270.63 and 108.62 seconds).
  The following complete node suite passed all 342 ordinary cases in 429.53
  seconds without competing native compilation. The withdrawal audit now caches
  at most 4,096 authenticated signed revisions and classifies owner metadata
  independently of checkpoint authorization; normal replay/recovery retain
  quorum validation. This removes redundant startup work across repeated
  historical revisions. These results are additional load/restart evidence;
  neither a demonstrated production fix for the network failures nor closure
  of the original R5 missing-signer gate.

  A fresh local Btrfs Git acceptance run on `3155689` passed its Git tests,
  extent checks, node Git/recovery tests, and stock-Git bridge, then timed out
  after 5,400 seconds in the five-daemon topology `backup --wait`. All members
  remained at guild event sequence 36; the coordinator reported one coding Add
  with only four of five signatures. The recovered storage peer exchanged relay
  traffic while other nodes repeatedly dialed its obsolete loopback endpoint. A
  separate direct smoke run passed. The failed run cleaned its temporary Btrfs
  image, daemons, namespaces, and firewall rules. Identify the missing signer
  and whether it is a transport failure or a conflicting signature lock,
  correct the cause, and repeat the full gate on exact committed source.
  `202aa44` promotes per-signer failures to warning logs. Two subsequent
  isolated smoke runs and the complete Git acceptance script passed on
  `31018a0` with stricter diagnostic backup timeouts (900/600 seconds), but
  did not reproduce the failure. The complete provisioned reflink script also
  passed on `6caeb11` with the 600-second diagnostic timeout. The expanded
  reflink script passed again on `d53b4be` with that timeout; one transient
  coding-activation request failure recovered before the topology completed.
  `31018a0` preserves relevant signer warnings in future timeout output. Keep this
  reliability issue open until the missing-signer path is explained and
  corrected. The full local Git gate passed again on `1d961d5`; during its
  five-daemon run, logs still showed transient four-of-five coding signatures
  and failed dials to obsolete loopback addresses before recovery completed.
  Source tracing found that coding and catch-up retries repeatedly add durable
  roster endpoints to the learned cache, while Identify can add further hints.
  Those hints could reintroduce an old direct address after a newer signed
  endpoint set replaced it. The current correction makes signed endpoint sets,
  including an empty withdrawal, authoritative over roster and Identify hints
  until expiry. The focused endpoint-cache and direct-to-relay regressions,
  130 other P2P tests, and strict workspace Clippy passed. The complete local
  Git acceptance script passed on exact commit `d49a0bf`, including all 62
  Btrfs Git cases and the five-daemon test (1,617.54 seconds); its disposable
  mount, daemons, namespaces, and firewall rules were cleaned up. Loopback
  retries and transient short signature quorums still appeared during topology
  transitions. The gate pass establishes recovery in this run, but not the
  cause of the original intermittent missing-signer stall; keep this item open
  until that path is explained and corrected.
  Source tracing found two further stale-address paths: persistent bootstrap
  and attempt-scoped recovery hints were still unioned with a newer signed
  endpoint set, and an in-flight dial to a withdrawn direct endpoint counted
  as evidence that the direct tier remained available. The current correction
  lets the signed set supersede those hints, moves tier selection to a current
  endpoint or healthy connection, and retries queued requests after replacement.
  A focused regression holds the obsolete direct dial pending while installing
  a signed relay endpoint, then checks relay selection and signed empty-set
  withdrawal. A subsequent same-tier correction binds each policy dial to the
  address set it started with. Replacing signed addresses supersedes the old
  attempt, allows a new dial immediately, and prevents a late old-dial failure
  from advancing transport fallback. A focused test holds the old direct dial
  pending while replacing it with another direct endpoint. The dial comparison
  normalizes the optional trailing peer ID, preserving relay-circuit dialing.
  Both signed-endpoint tests, four fallback tests, three selected-connection
  tests, and the relay-circuit test pass locally; strict workspace Clippy
  passes. Two long tests that failed amid broad parallel P2P execution pass
  individually. The broader missing-signer reliability gate remains open.
  The complete provisioned Git gate passed on exact commit `b69ce33`: all 62
  Btrfs Git cases, extent and node/recovery tests, stock-Git remote helper,
  and the five-daemon test (1,503.94 seconds). Its disposable mount, image,
  daemons, namespaces, links, and firewall chains were removed. The topology
  run nevertheless reproduced temporary four-of-five signatures at guild
  event sequence 36 and old loopback retries. Read-only status showed all four
  peers active, including increasing RelayFallback traffic to the recovered
  storage peer; read-only state copies showed the same proposed-event-37 lock
  prefix on all five members. The guild later advanced to event 42 and the
  backup committed. Thus stale loopback retries alone do not explain the
  missing response in this run. Identify the failing signer/request path and
  distinguish transport loss from signature collection or lock handling;
  plain lifecycle signer failures are currently logged only at debug level.
  The next source correction retains individually verified guild signatures in
  a versioned local record bound to the coordinator's durable proposal lock,
  guild, and event sequence. Plain lifecycle and bound coding Add retries reuse
  those signatures, contact only missing signers, and atomically retire the
  partial record when the event installs. A focused test proves accumulation
  across reopen and rejection of an invalid signature or changed proposal;
  existing guild administration and coding lifecycle tests, core guild tests,
  the locked all-target workspace suite (313 passing `mb-node` tests), and
  strict workspace Clippy pass. Plain lifecycle signer failures now name
  the member and sequence at warning level. This addresses the observed
  same-event partial-quorum loss. The complete provisioned Git gate passed on
  exact source `9f3bee0`, including all 62 Btrfs Git cases and the five-daemon
  test in 1,547.13 seconds; disposable Btrfs and network resources were
  removed. During that run, one recovered signer temporarily exhausted its
  transport tiers and then rejected event 27 while its guild state lagged;
  another topology pass had two transport-exhausted signers at event 39. The
  coordinator advanced through those partial quorums and the backup committed.
  Keep this reliability item open until the historical 5,400-second stall is
  excluded by stronger repeated topology evidence or its remaining response
  path is corrected; this one passing gate does not prove that every missing
  signer will eventually become reachable.
  The same-tier dial correction passed its exact-source local provisioned Git
  gate on `702fe63`. Clippy, 62 Btrfs Git cases, extent measurement, node Git
  and seed-recovery checks, and the stock-Git bridge passed first. The network
  script initially stopped before namespace setup because this shell omitted
  `/usr/sbin` from PATH; rerunning that final stage with the installed
  `iptables` on PATH passed the five-daemon topology/recovery test in 1,536.31
  seconds. The coordinator advanced past transient event-41 missing signatures
  and the recovered-topology backup committed. Old direct-address failures
  still occurred. Both disposable Btrfs mounts, images, daemon processes,
  namespaces, and firewall chains were removed. One more successful run does
  not exclude the intermittent long stall, so this reliability gate stays open.
  A source-level scheduling correction separates signed endpoint exchange from
  the peer-exchange loop's guild-tail request, which can wait up to 90 seconds
  for a slow advancing peer on every pass. Endpoint exchange can now circulate
  current signed addresses without waiting for that tail, while recovery-key
  and coding lifecycle proposals still follow the tail catch-up pass. Validate
  this change with the provisioned topology and keep the intermittent gate open
  until the missing-signer path is explained or repeatedly excluded. Formatting,
  strict workspace Clippy, the focused tail-selection test, and the provisioned
  five-node multi-owner QUIC/recovery test pass; the latter completed in 535.02
  seconds on a disposable local Btrfs image, which was unmounted and removed.
  The exact-commit `b25ae06` isolated five-daemon topology/recovery test passed
  in 1,637.58 seconds. Its relay-only transition again showed one signer
  exhausting transport tiers and then returning the generic guild-transition
  authorization rejection for event 28; a later event-29 request also exhausted
  tiers. During the final `backup --wait`, all active guild views reached event
  36 and the owner remained dirty for over five minutes despite an active
  RelayFallback path to the recovered storage peer. The job later advanced,
  committed, and seed recovery passed. The test removed its Btrfs image,
  mount, daemons, namespaces, and firewall chains. This run confirms eventual
  progress but does not explain or exclude the earlier 5,400-second stall.
  Source tracing found another diagnostic gap: the coordinator can wait for
  variable coding coverage while pending durable coding work exists, and that
  loop exposed the missing coverage only at debug level. A 60-second progress
  warning now names the checkpoint, guild event sequence, and coverage error;
  the coordinator's fetch, writer-key, packing, and lane-queue stages and the
  coding worker's four sequential steps also warn if any one stays pending for
  60 seconds. The warnings do not cancel work or change quorum decisions.
  Use the next local topology run to identify the stage behind a long pause.
  On exact commit `d0dddcb`, the isolated five-daemon topology/recovery test
  passed in 1,647.75 seconds with each topology backup bounded to 900 seconds.
  Its coding-coverage warnings showed the first recovered-topology checkpoint
  advancing from event 30 to 37 and the relay-only checkpoint from event 40 to
  43; no individual coding worker step logged a 60-second wait. Early signers
  still exhausted transport tiers and temporarily rejected lifecycle requests
  during recovery. The disposable Btrfs mount/image, daemons, namespaces, and
  firewall chains were removed. This run distinguishes slow serial group
  completion from a fixed sequence stall but does not explain the historical
  5,400-second timeout, so this gate remains open.
  `e65580f` installs a verified coding Add locally before concurrent peer
  dissemination and bounds its eager wait to 20 seconds. The focused activation
  test and strict workspace Clippy pass. The complete local Git acceptance gate
  passed on this exact commit, including 62 Btrfs Git cases, extent measurement,
  node/Git recovery, stock-Git exchange, and five-daemon topology/seed recovery
  in 1,618.57 seconds. Event 43 was reached after transient short lifecycle
  signature quorums, transport exhaustion, and stale-address dials. No coding
  dissemination timeout was observed, so this run does not verify that branch
  or explain the historical 5,400-second missing-signer stall. Keep open.
  `2b8c248` installs certified plain lifecycle events locally before concurrent
  peer dissemination with the same 20-second eager bound. A focused test holds
  one install response open, checks that the local tail is already installed,
  and exercises the bound; administration and coding activation tests and
  strict workspace Clippy pass. The isolated five-daemon topology and seed-only
  recovery test passed on this source in 1,490.34 seconds on fresh local Btrfs;
  its image, mount, and network namespaces were removed. During the run, a
  signer exhausted transport tiers and then rejected event 25 because the
  caller was not its configured coordinator; the guild later advanced.
  Investigate that pre-certification signer/authorization path separately.
  Bounded dissemination does not close the historical 5,400-second stall.
  `1b3f42a` adds recipient-side admission context and a distinct guild-member
  denial while preserving fail-closed authorization. The focused unrecovered
  signer and active-administration tests and strict workspace Clippy pass. Its
  isolated local topology/seed-recovery test passed in 1,428.25 seconds.
  `b3093a1` also captures warnings from both recovered daemons and includes the
  recovered relay member's log in timeout diagnostics. The revised isolated
  topology/seed-recovery test passed on exact commit `b3093a1` in 1,431.81
  seconds; all disposable Btrfs and network resources were removed. At event
  27, the recovered member logged `local_phase=None`, `local_sequence=None`,
  and no locally committed checkpoint before its restore adopted the guild.
  It correctly refused to sign until recovery completed, then became Active
  and the guild advanced. This explains that transient authorization rejection.
  The historical 5,400-second missing-signer stall and transport exhaustion
  remain unresolved; keep this gate open.
  `0d5af1d` stops majority-policy lifecycle and coding events as soon as their
  actual guild certificate verifies, releasing pending minority requests and
  outbound permits before installation. Its focused five-member majority,
  administration, coding activation, and slow-install tests pass, with strict
  workspace Clippy. The isolated five-daemon topology/seed-recovery gate using
  that network code passed in 1,569.46 seconds; its Btrfs image, mount, daemon
  processes, and namespaces were removed. Unanimous short quorums and transport
  exhaustion still appeared before the recovered guild caught up, so this run
  does not close the historical unanimous stall.
  A source trace found that a retiring duplicate connection prevented dispatch
  of every new request to that peer even when a separate healthy selected
  connection existed. Retirement can wait for unrelated inbound work, so this
  peer-wide hold could repeatedly delay a missing guild signature despite an
  active relay path. Exact-connection dispatch now proceeds on the healthy
  selected session while the short preferred-tier promotion wait remains.
  A focused P2P regression holds a duplicate in retirement and verifies the
  request uses the healthy session. The historical topology stall is not yet
  proven to have this cause; repeat the isolated five-daemon gate on committed
  source and keep the reliability item open until its response path is clear.
  The P2P suite also exposed an existing activation-fixture race on the prior
  committed tree: usable coverage can precede cleanup of the losing receipt,
  and one activation-worker turn need not process the intended pending job.
  The fixture now waits with bounds for those separate transitions and reports
  concise pending-job state on timeout. The full P2P suite passes with 135
  tests and 2 provisioned tests ignored; strict workspace Clippy passes.
  The isolated five-daemon topology and seed-recovery test passed on code
  commit `a870a46` in 1,497.88 seconds. Both recovered-topology backups
  committed despite transient missing signatures and coverage waits; the
  second backup advanced through event 43. Its local Btrfs image, mount,
  daemons, namespaces, and firewall rules were removed. This passing run
  validates the corrected request path in a real topology but does not prove
  it caused the historical 5,400-second stall, so this gate remains open.
  The complete local Git acceptance gate passed on exact committed source
  `9ec4953`: all 62 provisioned Btrfs Git cases, extent measurement, node
  recovery, stock-Git exchange, the raw-path CLI/daemon test, and five-daemon
  topology/seed recovery (1,522.23 seconds). The disposable image, mount,
  daemons, namespaces, and firewall rules were removed. The coordinator
  temporarily lacked p4's event-26 signature while its recovered daemon was
  unreachable, then received authorization denials during guild catch-up;
  later event-37 requests to two signers exhausted transport tiers, yet
  coding advanced and the backups committed. This passing run does not explain
  or exclude the historical long stall; keep the reliability item open.
  The isolated five-daemon topology and seed-recovery gate passed again on
  exact source `9f7d35b` in 1,467.50 seconds. The first local harness attempt
  stopped before daemon setup because its disposable Btrfs mount was root-owned;
  rerunning with that mount owned by the test user completed. During recovery,
  the coordinator retried event 25 with four of five signatures while the
  storage member's old endpoint was unreachable and its replacement caught up.
  A second short quorum at event 37 coincided with relay restart and missing
  circuit reservations; the relay-only backup advanced from event 38 through
  41, committed, and seed recovery passed. The local image, mount, daemons,
  namespaces, and firewall chains were cleaned up. This run adds successful
  retry evidence but still does not explain the historical 5,400-second stall.
  Startup now excludes the local peer ID from a generic bootstrap list before
  installing addresses or scheduling initial/retry dials. A focused test keeps
  a remote bootstrap peer while proving the own endpoint creates no policy
  dial. This removes one observed class of useless dial attempts, but it does
  not explain the missing remote signer or close this reliability gate.

## Milestone 6 retained native/shared implementation evidence

These completed entries record the implementation and checks at the time.
References to guarded fixtures below are historical evidence, not renewed FUSE
requirements. R7 reestablishes their shared recovery/retention coverage on the
native backend; canceled guarded-only gates do not block production.

- **M6 native source-backend binding — prior validation record.** The Git
  catalog binds its versioned local backend before publishing its ready marker
  and checks the binding before replay on reopen. Older unbound reflink catalogs
  migrate to `ReflinkV1`; unbound guarded catalogs fail closed instead of guessing
  anchor semantics. The earlier record reports focused reopen/mismatch tests,
  45 normal Git tests, all 62 ignored Git library cases on a fresh disposable
  local Btrfs image, and strict workspace Clippy passing; the image and mount
  were removed. This evidence does not close the remaining native-platform gates.

- [x] **M6 prune expired local Git blobs while unrelated revision GC remains
  pending.** The blanket `gc-anchor`/`gc-revision`/`gc-sector` gate prevented
  collection even after a historical blob lost all protection. Prune now uses
  verified retained graphs and exact sector-recipe anchor pins instead, while
  keeping capture, restore, and unfinished-backup fences. It also verifies and
  protects the direct parent checkpoint's graph during the one-generation GC
  grace window; seed recovery can lack its individual `user-revision` rows.
  The extended five-peer format-7 fixture commits replacement checkpoints with
  retention one: at generation 2, both the historical commit metadata and raw
  native blob survive pruning; at generation 3, expired raw sector recipes are
  gone, the independent historical anchor is physically removed, and a second
  prune removes nothing. The ext4 and fresh disposable local Btrfs runs pass
  in 243.93 and 320.95 seconds. All four guarded Git node probes and the native
  signed-revision prune test pass on that Btrfs image, as do formatting and
  strict locked all-target workspace Clippy in the pinned local development
  shell. The temporary mount and image were removed. Remote coded-data
  reclamation is a separate gate.
- [x] **M6 prove remote reclamation of expired Git history.** The five-peer
  format-7 QUIC fixture now starts the production holder-cleanup workers and
  verifies that the initial information and parity READY objects actually exist
  on their assigned holders. After history loses its last ref/pin, checkpoint 2
  retains its native anchor through the grace window; checkpoint 3 permits
  local pruning and the peer-reconciliation worker commits Retire/Forget for
  groups carrying obsolete packed sectors. Checkpoint 4 advances information
  GC. Direct reads on all five nodes then prove the expired READY information,
  old-group parity, packed caches, and raw history sectors are absent.
  The fixture confirms the latest checkpoint's seed-recovery readiness, stops
  the recovered owner and every task owning it, and removes its node state,
  source/view, adjacent native anchor/private-lower areas, and stock-Git export.
  A second fresh seed-only recovery reconstructs generation 4, the surviving
  graph and exact current files, with the expired blob absent. Its unstaged LF
  edit remains dirty while the committed CRLF blob retains one independent
  native anchor; unchanged blobs rebind to verified root files. Both loss
  simulations now erase adjacent owner payload areas. The final local ext4
  and disposable Btrfs runs, including the explicit readiness guard, pass in
  433.23 and 612.91 seconds. Formatting and strict locked all-target workspace
  Clippy pass in the pinned local shell. The
  temporary Btrfs mount and image were removed. This closes the local five-peer
  reclamation gate; the provisioned five-daemon guarded recovery, public guarded
  file operations, and full platform/backend gates remain open independently.
- [x] **M6 replace mixed packed coding groups before deleting expired data.**
  The coordinator now plans surviving packed sectors against verified groups
  whose non-padding information is all current. It queues replacement through
  the existing durable launch/verification/activation path while retaining the
  original group. Fully obsolete groups and ready Forget events run before
  replacement allocation; insufficient capacity preserves existing coverage.
  Packed checkpoints stay on the packed renewal path instead of falling through
  to raw-sector coding when their packed coverage is already complete.
  The new five-peer QUIC fixture starts with actual READY information and parity,
  drops a source from the packing catalog, protects its changed boundary sector,
  and shows that only the unchanged sector still relying on the mixed group
  needs replacement. After verified activation it commits Retire/Forget, checks
  physical deletion of old parity, retains obsolete information through the
  checkpoint GC grace window, then advances a correctly chained catalog and
  proves those READY information objects are deleted. Distributed reconstruction
  returns the exact surviving sector. The ext4 and disposable local Btrfs runs
  pass in 228.62 and 183.40 seconds. The guarded format-7 Git recovery/retention/
  prune fixture passes on that Btrfs image in 314.86 seconds.
  Adjacent redundant-group retirement, delayed-holder Forget cleanup, and
  offline-first-spare renewal regressions, formatting, and strict locked
  all-target workspace Clippy pass. The temporary Btrfs mount and image were
  removed. The end-to-end Git remote-reclamation gate is closed above;
  the provisioned daemon gate remains open.
- [x] **M6 Git file bytes remain exact under every supported command.**
  Native add hashes a pinned anchor, status and diff read raw worktree bytes,
  checkout restores anchor bytes, and the local Btrfs attributes regression
  now treats an LF-only edit as dirty, shows its raw diff, and restores the
  original CRLF bytes. A child-process Btrfs regression now runs under confirmed
  inherited `core.autocrlf`, `core.safecrlf`, environment `core.eol`, an external
  attributes file with text/filter/ident/encoding rules, configured
  clean/smudge/process commands, and `merge.renormalize`. Add, status, diff,
  restore, switch, ordinary-Git fetch/pull/push, and their blob IDs remain raw;
  no filter marker is created. The expanded local Btrfs regression also covers
  a system clean filter, a repository filter setting and `info/attributes` on
  the ordinary-Git side, native content merge, and linked-worktree checkout and
  merge, combined linked restore, and primary hard reset; its raw merged blob
  and restored bytes match. The inherited-config regression also checks that a
  line-ending-only edit blocks tracked `rm`, branch switch, and pull without
  changing the file or branch; its focused local Btrfs run passes. The
  command-by-command source trace in [docs/git-byte-audit.md](docs/git-byte-audit.md)
  covers every supported CLI command, including metadata-only operations and
  the stock-Git bridge. A fresh local Btrfs
  stock-Git round trip confirms that a CRLF worktree normalized by stock Git
  imports as its LF blob, remains clean until edited, restores the exact blob
  bytes, and exports the same object ID. The CLI help explains this limit.
  The complete local Git acceptance script passed on exact source `1d961d5`,
  including all 62 Btrfs Git library cases, extent measurements, node recovery,
  stock-Git remote helper, and five-daemon smoke. A separate alias-level
  remote-helper regression now calls `git status` through `mutualgit` under
  inherited `core.autocrlf`, external attributes, and a configured clean
  filter. It reports a raw-byte edit as dirty without running that filter;
  the focused local Btrfs test and strict workspace Clippy pass.
  The inherited-config Btrfs regression now also selects configured external
  diff, `textconv`, and merge drivers through attributes and checks that raw
  diff and built-in content merge do not invoke them. The ordinary-Git bare
  peer carries the same hostile rules during push/pull. Its focused local run
  passes with no driver marker created.
- [x] **M6 pull and merge operate from linked worktrees.** `mutualgit pull`
  and `mutualgit merge` now route through the selected linked worktree. Their
  conflict sessions, staged resolutions, status, and checkout replay use a
  linked namespace while the commit graph and refs stay shared. Local session,
  schema, CLI, and non-Btrfs Git checks pass. The new ignored Btrfs regression
  covers fast-forward and divergent clean pull, dirty-file refusal, conflicted
  merge, abort, resolution, continue, and interruption/reopen after generated
  blob capture, staged conflict resolution, and checkout publication without
  changing the primary worktree. Historical primary-keyed linked blob intents
  replay when their registered worktree still exists; a missing historical
  worktree now has a force-prune path that discards its private generated blob
  and retires the intent with its registration. The complete provisioned Git
  gate passed on `31018a0`, including the linked pull/merge Btrfs regression.
- [x] **M6 combined Git restore is one recoverable operation.**
  `mutualgit restore --staged --worktree PATH` now sends one daemon request for
  primary or linked worktrees. Version 11 checkout intents bind the selected
  HEAD paths, old worktree content roots, old index digest, and full target
  index; replay publishes selected worktree bytes before the index transition.
  Local intent, schema, CLI, and non-Btrfs Git tests pass. The ignored primary
  and linked Btrfs regressions cover dirty directory preflight, staged additions,
  unrelated staged bytes, and interruption/reopen before and after index publication.
  The complete provisioned reflink acceptance script passed on `6caeb11`.
- [x] **M6 prune duplicate native anchors by physical reachability.** Git
  prune now distinguishes exact index and local-sector recipe pins from blob
  IDs and retains one verified source per filesystem for each live blob. It
  removes surplus mappings with the existing crash-replayable deletion intent.
  Local decision and recipe-key tests pass. The new ignored Btrfs regression
  stages identical bytes repeatedly, prunes with and without an exact pin,
  and checks the remaining catalog after reopen. The node-level Btrfs case now
  also serves signed backup sectors across a reopen, restores exact worktree
  bytes, and proves a recipe pin survives revision-record removal until the
  sector recipe itself retires. The complete provisioned Git gate passed on
  `31018a0`, including the Btrfs and signed-revision prune regressions.
- [x] **M6 restore/reset recovery acceptance.** Checkout intent formats 9/10
  now carry BLAKE3 roots and lengths for previously unanchored working files;
  linked worktrees use wrapper version 2. Replay verifies those bytes in the
  worktree and private staging, and old pending intents without a provable
  original root fail closed. Local unit tests cover regular files, symlinks,
  conflicting content, staged-file replay, and primary/linked encoding. The
  linked Btrfs regression now also interrupts hard reset before file publication
  and after index publication, then reselects the linked worktree on reopen;
  its targeted local run passes. A provisioned Btrfs replay fixture now rejects
  a wrong native anchor behind the expected Git ID and an unverifiable legacy
  restore intent; its targeted run passes. The reflink acceptance script now
  includes these checks alongside primary and linked restore and hard reset.
  The complete provisioned reflink acceptance script passed on exact committed
  source `d53b4be`, including all new replay cases and the five-daemon smoke.
  Its disposable Btrfs image, namespaces, and firewall rules were cleaned up.

## Archived FUSE/guarded work — canceled direction, 2026-10-05

This section preserves prior implementation, source findings, and test results
for compatibility/removal review. It is not an active work queue. FUSE and all
unfinished guarded feature/fix gates below are canceled and superseded by R1;
statements such as "remain open," "implement," or "keep gated" describe the
historical plan only. Completed checkboxes record work performed, not current
product endorsement. Do not repair recapture isolation or finish guarded Git,
metadata, enrollment, mount, or edit-guard qualification as production work.

- [x] **M6 retain guarded creator ownership across replay, backup, and release.**
  FUSE file and directory creation now uses the request's UID/GID instead of
  assigning the root's owner. Setgid parents supply the inherited group and
  setgid bit on new directories. The lower inodes remain daemon-owned, with
  private directory modes; ownership is user-visible metadata. Version-2
  namespace/create records require an owner record bound to the view inode,
  root anchor, and native identity before publication. File intent and owner
  are recorded atomically; directory identity and owner advance together.
  Missing or mismatched ownership stops replay before namespace mutation.
  Historical version-1 records retain their original root-owner semantics.
  Abandoned directory/file creations and directory removal retire their owner
  record, and claim retirement clears the remaining ownership records after
  the release metadata is durable. Normal replay tests cover missing and
  mismatched owner records, abandoned creations, and directory identity
  publication. The privileged node regression verifies ordinary and setgid
  creation by a second user, populated-directory rename, remount, denied access
  by the root owner, exact CRLF/NUL bytes, signed backup/restore, and release
  with ownership intact. Mixed-owner initial enrollment, chown/ACL/xattr
  fidelity, recapture isolation, and full guarded milestone closure remain open.
  Local validation: all 135 normal store tests, strict locked all-target
  workspace Clippy, formatting, and diff checks pass. The new creator probe
  passed on ext4 (7.29 seconds) and a fresh disposable Btrfs image (13.70
  seconds); the existing 14-stage in-place replay probe passed on both (41.62
  and 104.03 seconds), as did all 18 privileged FUSE operation tests and nine
  mount/replay tests. The dedicated ENOSPC probe was outside this ownership
  slice. The Btrfs image, mount, and loop device were independently confirmed
  removed. Compilation and execution were local, with remote builders disabled.
- **Canceled / superseded by R1 — M6 recapture isolation.** Source
  review finds that `GuardedRootCapturePlan::prepare_file_edit_at` restores the
  working inode's original owner after detaching the first anchor, while a later
  `GuardedFileCapturePlan::capture` freezes and hard-links that inode without
  repeating private-owner isolation. A read-only lower descriptor retained
  before enrollment may therefore regain owner permission to `fchmod` and
  reopen `/proc/self/fd` for writing after recapture's short guard ends.
  Add a privileged regression for enrollment, first edit, stopped-view
  recapture, retained-descriptor writes, crash/reopen, and repeated edits on
  ext4 and Btrfs. Make each recapture's ownership transition durable and keep
  its anchor private until detach or retirement; verify normal release restores
  the user-visible owner. This is a source finding, not a completed runtime
  exploit proof. Keep mixed-owner enrollment and the complete guarded Git
  capture/checkout gate open until it is corrected and verified.
- **Canceled / superseded by R1 — M6 guarded Git integration.** The guarded FUSE view
  can recapture a stopped file and detach it on edit, but `SourceBackendKind`
  still rejects ordinary guarded Git add/checkout on a protected root. Bind
  each Git index/object pin to its guarded per-inode capture with a replayable
  handoff, and prove prune/root release cannot retire that anchor while Git
  retains it. Publish checkout files only
  through a guarded editable view, with byte-exact, no-copy and crash/reopen
  probes on ext4 and Btrfs. Keep the current guard until those proofs pass.
  The store now has a versioned per-file stopped-view attempt: preparation
  fences remount, startup completes the same capture after reopen, and its
  published record pins the root and file anchor until an owner releases it.
  The privileged ext4 and disposable local Btrfs probe covers a crash window
  after the hard-link anchor exists but before attempt publication, then edits
  the view and retries the same immutable capture. Published retries also
  verify the source plan against the exact mount claim; a normal unit test
  checks raw Unix path round-trip and malformed intent refusal. Both privileged
  runs pass, as do all 129 normal store tests and strict workspace Clippy. The
  node control store can now atomically transfer a published stopped-file
  attempt into durable file and root Git pins. Root and file retirement reject
  those pins across a control-store reopen; the privileged ext4 and Btrfs probe
  covers two pinned files, wrong-repository retirement, and last-pin release.
  The pin now records the exact attempt, worktree, raw path, and Git mode so a
  reopened node can enumerate and verify the pending stage without guessing;
  legacy pins missing that context fail closed. The node binds the
  repository to its protected root, reconciles pins after crashes, and publishes
  the corresponding Git catalog entry. The Git catalog now has a guarded-pin
  publication primitive: it atomically records the exact object mapping,
  worktree index entry, and attempt receipt, and replay leaves a newer index
  untouched. Its normal catalog tests cover reopen, retry, and wrong backend
  or root. The generic repository prune remains fenced for guarded roots; its
  old intent cannot safely see node-owned pins. The dedicated guarded path now
  uses a node-owned retirement fence. The node verifies guarded root, backend,
  and repository registration at startup,
  checks exact catalog receipts, rejects two unpublished stages for one path,
  and publishes missing receipts. The catalog is pinned in the private lower
  root and hidden from the FUSE worktree, whose mount lacks a stable native
  filesystem ID. A privileged ext4 and disposable local Btrfs node probe covers
  stopped-view capture, pin transfer, crash/reopen replay, raw blob ID, and
  idempotent reconciliation. Production guarded Git enrollment and stage are
  still gated on the live edit guard; guarded checkout, signed graph protection,
  and seed-only recovery remain open. An untouched original file now stages
  through a version-2 virtual file manifest over its verified root anchor,
  without adding a hard link or copying payload bytes. The ext4 and disposable
  Btrfs node probe stages untouched and already edited files, replays both
  catalog entries after reopen, then edits the untouched file without changing
  its staged bytes. Guarded prune now retires virtual mappings and their root
  pins together; seed-only recovery must rebind their root locators to the
  recovered anchor before guarded Git protection is enabled.
  Startup now also enumerates every guarded catalog receipt, checks it against
  node-owned pins, and rejects a root-backed virtual object map with no
  receipt; the node probe removes a pin after publication and confirms that
  reconciliation fails closed.
  The guarded catalog now exposes a read-only, versioned prune preview using
  the ordinary reachability calculation. It validates receipts and names
  candidate object IDs, exact manifests, and attempt IDs, including untouched
  files backed by version-2 virtual mappings. The preview leaves catalog
  mappings and node pins intact. Given a node-fenced batch and current signed
  roots, the catalog transition atomically deletes exact object mappings and
  receipts under a replayable catalog intent, rejects a stale candidate or
  changed protection root, and completes idempotently after reopen. The node
  now durably fences each batch before catalog retirement, records pin removal
  with an atomic progress marker, and replays the handoff before normal receipt
  reconciliation. A live guarded view still owns a per-file anchor through its
  mount claim: Git prune removes its mapping and pin but defers physical cleanup
  under a durable record until guarded-root release retires that claim. The
  privileged ext4 and disposable Btrfs probe covers root-backed virtual prune,
  per-file deferred cleanup, daemon reopen after catalog deletion, and an
  unrelated lost-pin failure. A second privileged ext4/Btrfs probe retires
  the mount claim and confirms that deferred cleanup then deletes the physical
  file anchor while preserving edited worktree bytes. The full separate-layout
  release probe now resumes before mount stop, after the release snapshot and
  claim retirement, and after deferred cleanup. The in-place release probe
  resumes after its claim retirement. Both pass on ext4 and disposable Btrfs,
  and verify the edited worktree bytes, removed file anchor, cleared cleanup
  record, and a second daemon reopen. An empty
  guarded Git repository can now be retired explicitly with
  `mutualgit deinit <repository-id>`. The catalog accepts only its exact backend
  binding and expected private files. The node fences their native identities
  before removing them. Startup replays an interrupted retirement before guarded
  mount recovery, then atomically removes the node registration; ext4 and
  disposable Btrfs probes cover normal retirement, replay after database
  deletion, and subsequent guarded-root release. Retained Git history or any
  unrecognized catalog state still blocks retirement. Guarded Git enrollment,
  checkout and complete format-7 network protection remain open. The guarded
  format-6 signer refuses a registered Git repository or a pending graph
  intent. Node preparation refuses a private catalog marker without matching
  registration before stopping the view; a registered, reconciled catalog now
  selects format-7 signing so its reachable history is not omitted. A separate
  format-7 private metadata type now validates a raw guarded namespace and
  root-bound Git graph; revision inspection can read it, and format-7 restore
  stages its guarded namespace and Git catalog with a guarded backend binding.
  Format-7 staging now verifies the catalog marker and exact private filenames,
  compares reachable refs, objects, HEAD, blob IDs and signed blob sectors,
  and binds the visible lower tree to its signed raw namespace while excluding
  only that bound catalog. An unexpected lower-tree name or catalog file fails
  verification. The guarded root recipe installer can now merge verified Git
  blob sectors with visible-file sectors and record each restored native anchor
  area. Format-7 restore from a fresh local node and authenticated sectors now
  replays that installer through the supervised guarded mount, registers the
  recovered Git catalog, and verifies the signed graph again after mount. A
  privileged ext4 and disposable local Btrfs probe restores a reachable commit
  and blob, hides the catalog from
  the FUSE view, interrupts after recipe installation, reopens to finish the
  mount, then edits the visible file without changing its signed blob or
  sector recipes and reopens the completed recovery. Finish broader multi-blob
  source-loss cases and the no-duplicate payload proof before enabling ordinary
  guarded Git enrollment and file commands. A provisioned five-member seed-only
  network recovery gate with a format-7 packing checkpoint remains open.
  Linux Git blob recovery streams verified sectors into a sparse native anchor
  without a temporary worktree payload or reflink. When a signed Git sector
  is also a visible guarded-file sector, recovery now retains the root-anchor
  recipe instead of replacing it with the imported Git anchor. The privileged
  ext4 and Btrfs probe confirms that the imported anchor no longer owns those
  sector recipes after the mount. The store now derives a verified virtual Git
  manifest from a published, still-frozen root file without another hard link.
  The node now durably pins that root before the catalog atomically changes the
  imported blob's mapping to the virtual manifest under the same object-map ID.
  Startup replays a crash after the pin write, checks the catalog receipt against
  the node pin, and removes the unreferenced imported payload. The privileged
  ext4 and Btrfs recovery probes confirm the imported anchor is gone, the
  signed blob remains readable after a visible edit and daemon reopen, and a
  new virtual mapping is rejected once the file becomes editable. Guarded
  prune now treats a recovered virtual mapping as a distinct candidate: its
  catalog transition removes the object map and recovery receipt together,
  and the node retires the matching recovery pin and last Git root pin with a
  durable progress marker. An interrupted catalog deletion replays before
  normal pin reconciliation. The ext4 and Btrfs probes retain the live graph,
  then remove local ref/index reachability in the synthetic fixture, interrupt
  after catalog retirement, and confirm replay releases only Git ownership
  while the edited visible file and signed root recipe survive. Broader
  multi-blob/source-loss cases and the format-7 five-member network gate remain
  open. The guarded signer captures the registered private Git catalog into a
  durable graph intent before stopping the view, signs reachable objects and
  blob sectors with the guarded namespace, keeps shared visible-file recipes,
  and retains the intent across startup while a stopped capture owns its
  anchors. A signed-mode record makes committed retries independent of local
  metadata recipes. A normal catalog-intent test and privileged ext4 and
  disposable Btrfs probes cover a reachable commit/blob, intent retention
  through startup reconciliation,
  sector-recipe sharing, signing, and retry. A further ext4/Btrfs node probe
  stages an untouched root file with a node-owned pin, reopens to publish its
  catalog receipt, creates a real guarded Git commit without checkout replay,
  then reopens again with a stopped graph capture and signs its reachable blob.
  Node revision preparation now selects this path for a registered and
  reconciled guarded catalog, while refusing an unregistered private marker.
  A five-member in-memory guild test signs this graph through the production
  node path, deletes the owner's node state and source, reconstructs sectors
  from other members, and restores two exact files and reachable Git blobs on
  ext4 and disposable Btrfs. It checks that the signed data sector IDs are
  unique and both recovered blobs use virtual mappings to the one retained
  guarded root anchor, with no separate blob-owned sector recipes. Broader
  blob-only and edited-file physical-reclamation cases remain. That lab uses
  a format-3 checkpoint. A separate five-peer QUIC fixture now uses the
  production backup coordinator to pack a guarded Git graph with those two
  untouched files plus one file edited through FUSE before staging into a
  quorum-signed format-7 checkpoint. It deletes the owner's node state and
  source, then recovers all three raw files and reachable Git objects from a
  fresh node on ext4 and disposable Btrfs. The provisioned five-daemon
  topology and its failure-domain/source-loss gate remain open; the QUIC
  fixture runs all five peers in one process. Recovered guarded catalogs now
  support verified `status`, `log`, branch/tag listing, and raw `diff` through
  a descriptor-pinned inspection reader that does not require a durable UUID
  from the FUSE view. The same ext4/Btrfs QUIC fixture checks that status
  reports the format-7 history as backed up, a later FUSE edit appears in raw
  status/diff without changing the signed blob, and `add` still refuses the
  guarded root. The recovered graph can now export into a stock Git object
  database; after the FUSE edit, ext4/Btrfs fixtures verify both exported blob
  bytes and the commit ID against the signed history. The node now owns the
  checked stopped-view file stage sequence: it validates a registered catalog
  and raw path before stopping FUSE, transfers the exact capture to a durable
  node pin, remounts, then reconciles and verifies the catalog entry. The
  mixed three-file format-7 QUIC recovery fixture uses this routine, checks
  the edited file's format-1 stage anchor and its recovered root-backed
  virtual blob, and passes on ext4 and disposable local Btrfs; strict workspace
  Clippy passes. Guarded Git catalog initialization and node registration now
  share a checked node routine: a private catalog created before registration
  can be registered after node restart, and repeated init preserves the same
  identity. The privileged registration replay probe passes on ext4 and disposable
  Btrfs; the format-7 QUIC fixture passes with this init path on ext4 and
  Btrfs. Public guarded enrollment, add/checkout, and the provisioned daemon
  gate remain open.
  A node-owned initialization intent now precedes any private catalog creation.
  Startup verifies its protected root, guarded claim and backend, completes a
  partial Git catalog before remounting FUSE, registers the repository, then
  clears the intent. An unmarked `.mutualbackup` directory without that intent
  is refused before mutation. The focused crash probe covers an unmarked
  directory with Git's partial init marker, refusal of root removal while the
  intent is pending, daemon reopen, exact-byte stage, and idempotent init on
  ext4 and disposable Btrfs. The mixed three-file
  format-7 five-peer QUIC fixture passes on both filesystems with the journal;
  the provisioned five-daemon gate remains open.
  `mutualgit` now falls back to a read-only daemon directory lookup when the
  FUSE worktree hides the private catalog marker. The node verifies the
  protected-root registration and backend before returning its Git ID; local
  marker discovery still handles ordinary and linked worktrees. The local
  control schema covers raw Unix paths, the CLI fallback uses a framed-socket
  regression, and guarded ext4/Btrfs plus ordinary Btrfs node probes pass. The
  five-peer format-7 seed-only recovery fixture also locates the hidden-catalog
  repository on ext4 and disposable Btrfs.
  The stock-Git remote helper now uses that lookup for an exact hidden-catalog
  repository path. Its local Btrfs bridge gate fetches a raw blob through a
  marker-free view path and verifies the exported bytes. This makes recovered
  guarded history discoverable to both frontends while guarded add/checkout
  and the provisioned daemon gate remain open.
  The five-peer format-7 recovery fixture now serves the actual local-control
  listener from the recovered node and confirms hidden-catalog lookup,
  backed-up Git status, and stock-Git object export over its framed socket;
  the exported commits and raw blobs pass on ext4 and disposable Btrfs.
  The fixture now commits a fourth file, removes its visible name and index
  entry in a second commit, and retains its bytes through the older commit.
  Guarded index-only removal uses the backend's pending-operation validation
  rather than entering reflink checkout replay against the FUSE filesystem.
  Seed-only recovery keeps the historical blob in a separate native anchor,
  leaves its name absent from the current view, and exports its exact bytes;
  the three current blobs still use virtual mappings to one root anchor.
  The ext4 and disposable-Btrfs runs, 52 normal Git library tests, and strict
  workspace Clippy in the pinned development shell pass. Public guarded
  add/checkout, historical-blob physical reclamation, and the provisioned
  five-daemon gate remain open.
  Branch and tag creation/deletion, explicit commit pins, and same-tree branch
  switching now use guarded metadata validation instead of reflink checkout
  replay. A pending catalog retirement blocks those mutations; a switch that
  would replace file bytes remains explicitly gated. Branch and pin changes
  durably mark the root dirty for a new backup, including branch edits through
  a linked reflink worktree. The expanded five-peer format-7 fixture retains
  its history-only file on an unselected branch, restores that branch and blob
  from the seed, switches same-tree branches without changing a dirty file,
  and exercises tags and pins against the recovered private catalog. After
  removing the historical branch and its pin through the production node and
  local-control paths, prune removes only a newly created/deleted annotated
  tag: the retained signed checkpoint still protects the historical commit
  graph and native blob. The fixture passes locally on ext4 (174.04 seconds)
  and disposable Btrfs (219.10 seconds); all four guarded Git node probes,
  52 normal Git library tests, all 62 provisioned Git library cases on a fresh
  local Btrfs image, the three native node init/linked-worktree/retention
  probes, formatting, and strict all-target workspace Clippy pass. Actual
  history expiry across replacement checkpoints and remote/physical deletion
  were not covered by that run. File-changing guarded commands and the
  provisioned daemon gate remain open; local expiry is covered below.
- [x] **M6 preserve recipe pins during guarded Git prune replay.** A pending
  catalog retirement no longer authorizes deletion of an imported native anchor
  when a retained or restored local-sector recipe names that exact anchor.
  The node rechecks current recipe pins before replay cleanup and keeps its
  retirement fence pending while such a pin exists. The new privileged
  regression first proves ordinary prune preserves a pinned history-only blob,
  then interrupts after catalog retirement, restores its recipe, verifies
  replay and startup fail closed with the anchor and ciphertext intact, and
  finally retires the recipe and reopens to finish physical deletion.
  It reproduced the pre-fix failure and passes on ext4 and disposable local
  Btrfs. The existing stage/pin replay and deferred-cleanup probes pass on ext4;
  all four guarded Git node probes pass on Btrfs. Strict locked all-target
  workspace Clippy passes in the pinned local development shell. Broader
  signed-history expiry and remote-sector reclamation remain required.
- **Canceled / superseded by R1 — M6 guarded edit guard.** The store now has replayable per-file and
  whole-root sparse detaches. Ordinary `root add` still selects the reflink
  backend; explicit `root add-guarded` now begins a guarded enrollment from a
  separate private lower tree and empty view, while `root add-guarded-here`
  migrates a user-owned root at its original path. Implement and locally probe a
  long-lived access decision that permits normal reads without detaching every
  anchor and prevents writes until detach is durable, even after owner `chmod`,
  pathname truncate,
  pre-opened handles, rename, and restart. `FAN_PRE_ACCESS` covers both reads
  and writes and reports a range rather than an edit intent, so it cannot be
  used alone as a write detector. Use the versioned FUSE worktree view specified
  in the plan: pass through reads of frozen inodes, complete durable detach
  before writable opens, shared mappings, truncate, allocation, or `chmod`,
  and fail closed on mount/daemon loss. The existing 10 link-freeze and 2
  guarded-root privileged tests pass locally on Linux 7.2.5; they cover
  short-lived freeze and replay, not this long-lived view. `b53be0b` adds a
  disposable FUSE passthrough probe, passing locally on ext4 and a fresh Btrfs
  loop image: it reads exact bytes through a shared read-only mapping, rejects
  a writable open in the FUSE handler, and keeps the lower inode unchanged
  after read-only `O_TRUNC` and owner `chmod` attempts. `eac567e` also
  proves an ordinary user can read the view but cannot access the private
  lower source on both filesystems. `e4f4147` connects a single captured file
  to its durable detach journal before FUSE `O_WRONLY` and `O_RDWR` passthrough;
  ordinary-user writes retain the original source inode and leave a distinct,
  byte-exact anchor on ext4 and fresh Btrfs. `2cf0cb3` extends that single-file
  probe to owner `chmod`, pathname truncate, and `O_TRUNC` open: each completes
  detach before changing the source inode, retains the exact anchor bytes, and
  passes as an ordinary user on ext4 and fresh local Btrfs. The five privileged
  FUSE probes, normal store library tests, formatting, and strict locked
  workspace Clippy pass. `7f52416` adds single-file view rename/unlink handling:
  rename leaves the captured hard-link
  anchor frozen until a later write at the new name detaches it, and unlink
  removes the working name while the exact anchor remains. All seven privileged
  FUSE probes pass on ext4 and fresh local Btrfs. `33e8171` adds a guarded
  `fallocate` callback and an ordinary-user allocation probe: an allocation
  extending the editable file to 4 KiB leaves the original anchor byte-exact.
  All eight privileged FUSE probes pass on ext4 and fresh local Btrfs; normal
  store tests and strict workspace Clippy pass. `7110990` indexes a flat FUSE
  namespace by inode and name. Its two-file probe uses a real guarded-root
  capture: editing one file leaves the other frozen, and rename plus later edit
  dispatches to the correct file's detach journal. All nine privileged probes
  pass on ext4 and fresh local Btrfs, with normal store tests and strict locked
  workspace Clippy passing. `712a62f` adds a nested directory to the view:
  ordinary-user listing, read, same-directory rename, and later edit of a
  captured nested file preserve its anchor and leave another file frozen.
  An unsupported directory rename fails closed. All ten privileged probes
  pass on ext4 and fresh local Btrfs; store tests and strict locked workspace
  Clippy pass. `4d5c804` moves a frozen file out of a nested directory and
  back using pinned source directories; the later edit detaches the correct
  anchor. A move onto an existing tracked name fails without changing either
  file. An uncertain move failure poisons the probe view so later requests
  fail closed. The ten privileged probes pass on ext4 and fresh local Btrfs,
  along with normal store tests and strict workspace Clippy. `6147a32`
  constructs the experimental FUSE view from a published guarded manifest and
  its stored plan, checking the pinned source root, each directory and file
  identity, and anchor availability. The two-file and nested probes use this
  constructor and pass on ext4 and fresh local Btrfs. The next slice records
  file rename and unlink intents in the control store before lower-directory
  mutation. Rebuild replays an interrupted operation against the captured file
  identity, refuses a replacement identity, and restores renamed and deleted
  entries across actual FUSE remounts, including nested moves and an empty
  root. The following slice publishes new files from anonymous inodes only
  after a durable creation intent names their native identity. Reopen either
  discards an unpublished intent or verifies and finishes its visible file;
  a foreign target fails closed. Ordinary-user creation in the root and a
  nested directory, rename, writable reopen, unlink, and FUSE remount pass on
  ext4 and fresh local Btrfs. Atomic replacement now journals one two-inode
  exchange, publishes both namespace records together, and conditionally
  removes the displaced inode. Restart finishes the operation at each
  exchange, publication, and cleanup boundary, and refuses a foreign target.
  Ordinary-user replacement of a still-frozen captured file and a
  cross-directory replacement preserve exact anchors through remount.
  Guarded `mkdir` now stages an empty directory in the protected same-filesystem
  anchor area, records its native identity before moving it into the worktree,
  and rebuilds the directory map after restart. Ordinary-user nested directory
  and file creation survive FUSE remount; interruption tests cover each staging
  and publication boundary and reject a foreign target without deleting it.
  Empty dynamically created directories can now be removed through the view.
  Removal writes a durable intent before the lower `rmdir`, and remount either
  finishes the removal or rejects a foreign replacement. Nested removal after
  file unlink and a second FUSE remount pass on ext4 and fresh local Btrfs.
  Captured empty directories now use their manifest-bound native identity and
  the same removal journal; a tombstone survives remount without requiring
  the original worktree path to exist. The nested captured-directory probe
  removes its last file, removes the directory, and remounts successfully on
  both filesystems. Directory reconstruction indexes captured and dynamically
  created directories together by their durable current paths. Directory
  rename now journals the native identity and old/new names before the pinned
  lower move, then atomically publishes the new paths of every tracked
  descendant and retires the intent. Reopen finishes either side of the move,
  and a foreign target fails closed. Ordinary-user FUSE probes rename a
  populated captured subtree beneath a dynamic parent, edit its captured file
  without changing the anchor, then rename the captured and dynamic subtrees
  again across remounts. The 109 normal store tests, 12 privileged FUSE probes
  on ext4 and fresh local Btrfs, and strict workspace Clippy pass. Remaining
  metadata and allocation modes, concurrent handles, mount
  supervision/recovery, and whole-worktree enrollment remain open.
  Captured-file owner `chmod` now survives guarded-view
  remount: rebuild advertises the original mode while the lower inode is
  guard-frozen, then uses the lower mode only after the durable edit journal
  proves that inode independently editable. A nested-file probe checks the
  frozen visible mode and the later `0640` mode across remount on ext4 and
  fresh local Btrfs. The 109 normal store tests, all 12 privileged probes,
  formatting, and strict workspace Clippy pass on this correction.
  Empty-target directory replacement now journals both native identities,
  exchanges the directory names, removes the displaced empty target, and
  atomically publishes descendant paths with a target tombstone. Replay
  covers intent, exchange, cleanup, and publication boundaries; nonempty or
  foreign targets fail closed. An ordinary-user FUSE probe rejects a nonempty
  target, replaces an empty dynamic directory with a populated captured tree,
  and rebuilds it after remount. The 112 normal store tests, all 12 privileged
  FUSE probes on ext4 and fresh local Btrfs, formatting, and strict workspace
  Clippy pass on this slice.
  Root, captured-directory, and dynamic-directory owner `chmod` now survive
  guarded-view remount. The root mode is kept in a durable local view record so
  the private lower root remains `0700`; child directory modes use their
  unfrozen lower inodes. Ordinary-user probes check all three modes before and
  after remount on ext4 and fresh local Btrfs. The virtual root-mode record is
  not yet carried by protected owner revision metadata for seed-only recovery;
  guarded enrollment stays gated until that and the remaining metadata,
  concurrent-handle, and mount-supervision work are complete.
  Writable FUSE handles now retain the detached source descriptor. Handle-based
  truncate and allocation continue to address that inode after unlink or
  atomic replacement instead of reopening the old pathname. The ordinary-user
  two-file probe exercises both cases, checks the replacement and captured
  anchors remain byte-exact, and passes with 112 normal store tests and all 12
  privileged probes on ext4 and fresh local Btrfs; formatting and strict
  workspace Clippy pass. Broader concurrent-handle interleavings and mount
  supervision remain open.
  An additional ordinary-user probe confirms `fchmod` on a read-only handle
  first detaches the source and changes its visible mode while the private
  anchor remains byte-exact at its protected mode; it passes on ext4 and fresh
  local Btrfs.
  Regular-file `atime` and `mtime` now come from the source inode rather than
  epoch placeholders. Owner `utime` detaches a frozen file before changing its
  nanosecond timestamps; its privileged probe passes on ext4 and fresh local
  Btrfs. The 112 normal store tests, all 13 privileged guarded probes on both
  filesystems, formatting, and strict workspace Clippy pass. Protected
  root-mode recovery and mount supervision remain open.
  The two-file guarded-root probe also sets nanosecond timestamps on a newly
  created file after atomic replacement, remounts the view, and verifies the
  rebuilt attributes on ext4 and fresh local Btrfs.
  Root, captured-directory, and dynamic-directory access/modified times now
  come from identity-checked lower descriptors. Owner `utime` writes them to
  the pinned directory, with root permission bits still virtual and the private
  lower root still `0700`. The ordinary-user nested probe checks nanosecond
  timestamps for all three directory kinds after FUSE remount on ext4 and fresh
  local Btrfs. The 112 normal store tests, all 13 privileged probes on both
  filesystems, formatting, and strict workspace Clippy pass. Protected
  root-mode recovery and mount supervision remain open.
  The view now reports native `ctime` with nanosecond precision for files,
  root, captured directories, and dynamic directories. The conversion also
  handles pre-epoch timestamps. Ordinary-user probes compare view and lower
  `ctime` on ext4 and fresh local Btrfs, including after remount. The 113
  normal store tests, all 13 privileged probes on both filesystems, formatting,
  and strict workspace Clippy pass. Protected recovery of the full metadata
  set and the remaining guarded enrollment gates are still open.
  Shared writable mapping now has an ordinary-user first-mutation probe: the
  mapping writes the detached source and leaves captured bytes exact. A new
  eight-thread probe exposed overlapping writable opens failing with `EIO`:
  the kernel requires all live passthrough handles for one FUSE inode to reuse
  one backing registration. The view now shares that registration while each
  handle retains its own descriptor. Eight simultaneous writable opens and
  mixed read-only/writable handles pass on ext4 and fresh local Btrfs, as do
  113 normal store tests, all 16 privileged guarded probes on both filesystems,
  formatting, and strict workspace Clippy. Broader rename/unlink interleavings,
  mount supervision, and guarded enrollment remain open.
  The two-file probe now keeps two writable handles open across atomic
  replacement and unlink. Truncate through one and allocation through the
  other continue to affect only the displaced/unlinked inode, while the new
  name and captured anchors remain exact on ext4 and fresh local Btrfs.
  Guarded passthrough open and create now accept `O_APPEND`. An ordinary-user
  append probe seeks back to the start before writing and still appends after
  durable detach; a newly created file also appends through its first handle.
  All 17 privileged FUSE probes pass on ext4 and fresh local Btrfs.
  A separate-process crash probe now kills the FUSE daemon after a successful
  ordinary-user read, then verifies new view access fails and the same user
  still cannot open the private lower file. All 18 privileged FUSE probes pass
  on fresh local Btrfs; the crash probe also passes on ext4. This proves the
  observed fail-closed kernel behavior, while supervised remount, recovered
  metadata, and guarded enrollment remain open.
  The FUSE view now handles file `fsync`/`fdatasync` through the retained source
  descriptor. `opendir` pins an identity-checked lower descriptor; `fsyncdir`
  uses it after rename or replacement removes the old name, and `readdir` and
  `releasedir` validate its handle. An ordinary-user probe syncs a captured
  directory after rename, the displaced directory after replacement, and newly
  created and detached files. All 18 privileged guarded-view probes pass on
  fresh local ext4; the renamed-directory probe passes on fresh local Btrfs.
  The 113 normal store tests, formatting, and strict workspace Clippy pass.
  Mount supervision and protected view-metadata recovery remain open.
  A store-level guarded mount now records the lower-root and placeholder inode
  identities before mounting, refuses a live or foreign mount, and detaches
  only its claimed dead FUSE mount before rebuilding the captured view. Its
  privileged test verifies ordinary-user access, private-lower denial, clean
  remount, killed-daemon remount, and rejection of a replaced placeholder on
  ext4 and a fresh local Btrfs image. The 114 normal store tests and strict
  workspace Clippy pass. Daemon ownership/health supervision, protected
  metadata recovery, and the replayable enrollment transition remain open.
  The production mount now enables kernel default permission checks for its
  advertised view modes. A privileged probe proves that without this option
  an unrelated user can read a `0700` view; with it, that user is denied and
  the intended owner can still edit after durable detach without changing the
  frozen anchor. The edit survives clean and killed-daemon remount on ext4 and
  fresh local Btrfs. Daemon supervision and enrollment remain open.
  The raw guarded FUSE filesystem type is now crate-private, so callers use
  the mount wrapper that enforces permission and mount-identity checks. All
  18 privileged view probes now mount with kernel default permission checking
  and pass on ext4 and fresh local Btrfs, as does the claimed-mount recovery
  test. Normal store tests, formatting, and strict workspace Clippy pass.
  Claimed-mount recovery now reads the published manifest from its sealed
  anchor catalog and verifies it against the durable plan and manifest claim;
  no caller-held manifest is needed after a daemon restart. The privileged
  test reopens `control.db`, recovers after clean and killed-process unmounts
  on ext4 and fresh local Btrfs, and keeps the private lower root inaccessible.
  A normal test rejects altered sealed catalog bytes. The 115 normal store
  tests, formatting, and strict workspace Clippy pass. Seed-only recovery of
  mutable view metadata and node enrollment remain open.
  Guarded root retirement now refuses any live mount claim. An explicit,
  identity-checked claim retirement requires the view to be unmounted, writes
  a durable remount fence, and removes the claim before anchor GC may proceed.
  The privileged lifecycle test rejects retirement while mounted, then retires
  the claim and frees the guarded anchor after stop; it passes on ext4 and a
  fresh local Btrfs image. Node GC still needs to call this transition only
  after all signed revisions and Git pins release the anchor.
  The guarded FUSE view now reports filesystem capacity and name limits from
  its pinned lower-root descriptor instead of the default zero-capacity reply.
  An ordinary-user `statvfs` probe and native-geometry comparison pass on
  ext4 and fresh local Btrfs; 115 normal store tests, formatting, and strict
  workspace Clippy pass. This does not close protected mutable-view recovery,
  daemon supervision, or guarded enrollment.
  The sparse-detach replay test now injects `ENOSPC` after a staging write.
  On ext4 and fresh local Btrfs, the error leaves the edit journal in
  `CopyStaging`, the shared source frozen, and the captured anchor exact;
  retry removes the incomplete staging file and finishes the detach. A separate
  privileged test now fills disposable 192 MiB ext4 and 384 MiB Btrfs images
  until real `ENOSPC`, then frees less space than the 32 MiB detach needs. On
  both, the sparse copy leaves a partial staging file, the source remains
  frozen, and the anchor stays byte-exact; removing the filler permits replay
  and a later edit without changing the anchor. The test checks a disposable
  mount marker, separate device, and 512 MiB capacity bound before filling.
  The checked FUSE view now preserves the underlying `ENOSPC` through guarded
  writable-open and pathname-truncate replies instead of reporting `EIO`.
  An ordinary-user test on fresh disposable ext4 and Btrfs images confirms
  both operations return `ENOSPC`; the shared source stays frozen, its private
  lower path remains inaccessible, and the anchor stays exact. After space is
  freed, a clean stop and claimed remount replay the edit successfully.
  All 18 privileged guarded-view probes pass on ext4 and fresh local Btrfs;
  115 normal store tests, formatting, and strict workspace Clippy pass.
  The daemon now recovers every active guarded mount claim before serving
  requests, retains its FUSE session for the process lifetime, and checks
  mount health every five seconds. Interrupted claim retirement is finished
  instead of remounted. A privileged node test verifies clean startup
  recovery, detection of an externally detached view, another restart,
  ordinary-user edit, and claim retirement on ext4 and fresh local Btrfs.
  The live mount now retains its exact durable claim. The daemon health check
  verifies that claim has not changed and that the private lower directory
  still has its recorded native identity; it exposes that verified binding
  for the eventual protected-root enrollment path. The privileged node
  restart test now corrupts the claim while FUSE remains live and confirms
  fail-closed health, then restores it. That test passes locally on ext4 and
  disposable Btrfs, as do normal store tests and strict workspace Clippy.
  Guarded root enrollment and seed-only recovery of mutable view state still
  need their own implementation and acceptance gate.
  A disposable local pre-opened-descriptor probe exposed an enrollment
  escape: a view-owned frozen file can be `fchmod`ed through a retained
  read-only descriptor, then reopened writable through `/proc/self/fd`,
  changing its hard-link anchor even when the lower root is private `0700`.
  The mount wrapper now refuses such frozen anchors and refuses lower child
  directories owned by the view user or writable by group/others before it
  records a new claim. A privileged regression covers the refusal. Enrollment
  still needs durable lower-inode ownership/mode isolation, virtual metadata
  with signed recovery, and an end-to-end pre-opened-handle probe before it can
  admit ordinary user-owned trees. The refusal regression, all 18 privileged
  guarded-view probes, and the node mount-restart probe pass on ext4 and fresh
  local Btrfs; 115 normal store tests, formatting, and strict workspace Clippy
  pass.
  A focused privileged probe now holds ordinary-user read-only file and
  directory descriptors across capture, then manually isolates the lower
  ownership and mode before mounting. It confirms `fchmod`, writable
  `/proc/self/fd` reopen, and retained-directory lookup fail, while a FUSE edit
  leaves the frozen anchor byte-exact. It passes on ext4 and fresh local Btrfs.
  The manual ownership step is not a replayable enrollment transition and does
  not protect mutable view metadata in signed recovery, so enrollment remains
  gated.
  New guarded-view directories now keep their lower inodes at `0700`, while an
  atomic create intent and virtual mode record preserve the requested mode
  through replay and remount. Owner `chmod` of captured and dynamic directories
  changes that virtual mode without widening lower access. A privileged mount
  probe verifies that an ordinary-user `0777` directory stays `0700` below the
  view before and after remount; the nested guarded probe checks the same for
  captured and newly created directories. All 18 privileged guarded-view
  probes pass on ext4 and, sequentially, fresh local Btrfs; the mount-recovery
  probe passes on both, as do 115 normal store tests and strict workspace
  Clippy. Existing captured lower directories still need a replayable
  ownership/mode isolation transition, and virtual view modes still need
  protected seed-only recovery before guarded enrollment can be enabled.
  Directory replacement now retires the displaced inode's virtual mode in
  the same durable commit as its namespace tombstone; source modes survive
  the move. Replay tests cover every exchange/removal/commit boundary, and
  directory removal replay also checks mode retirement. All 115 normal store
  tests and strict workspace Clippy pass.
  Mount admission now rejects lower child directories with any group/other
  access, including search-only `0711`: a retained descriptor to that child
  would bypass the private root path. The privileged refusal probe and an
  extended held-descriptor probe, which includes a nested child, pass on ext4
  and fresh local Btrfs. The actual enrollment transition remains gated.
  First-mount admission now checks every captured lower directory's identity
  and private owner/mode before rebuilding any FUSE namespace journal. An
  unsafe nested directory wins over a malformed pending rename record, which
  remains untouched, so failed admission cannot replay namespace mutations
  first. The privileged refusal probe passes on ext4 and fresh local Btrfs;
  the successful held-descriptor mount probe passes on both, as do 115 normal
  store tests and strict workspace Clippy. Durable ownership isolation and
  protected view-metadata recovery remain open.
  A versioned lower-ownership snapshot now durably binds the published capture
  plan to every captured root, directory, and frozen file identity, UID, GID,
  pre-isolation mode, and access ACL before any ownership transition. The
  file-freeze journal separately retains the original file access state.
  Reopen verifies its format and plan binding; cancellation rechecks frozen
  bytes and original metadata, and anchor retirement refuses a surviving
  record. A privileged
  probe changes a frozen file's owner after the snapshot, confirms cancellation
  and retirement fail closed, restores the owner, and then cancels and retires;
  it passes on ext4 and fresh local Btrfs. All 115 normal store tests and strict
  workspace Clippy pass. The actual guarded ownership/mode transition, its
  replay and restoration, and signed recovery of mutable view metadata remain
  open; this snapshot alone does not make the lower tree private.
  A per-file owner-isolation record now precedes `fchown` of a verified frozen
  hard-link inode while its write-exclusion guard is held. The root pass reads
  original UID/GID from the durable lower snapshot and resumes after a partial
  file pass. A privileged ordinary-user probe holds a read-only descriptor
  across capture and isolation, then confirms `fchmod` and writable
  `/proc/self/fd` reopen fail; exact anchor bytes and replay pass on ext4 and
  fresh local Btrfs. Files with access ACLs or file capabilities are refused
  before the ownership change until those metadata rules are implemented.
  A frozen, owner-isolated file can now retire after its anchor is unlinked:
  the retirement journal restores its recorded UID/GID and original access,
  then removes the owner record only after the capture is retired. Restart
  probes cover interruption after unlink and after `fchown`; the held-descriptor
  probe also verifies final restoration. These pass on ext4 and fresh local
  Btrfs, alongside 115 normal store tests and strict workspace Clippy.
  Root retirement now consumes the lower-ownership snapshot after all captured
  file journals finish: it preflights unchanged root/directory metadata and
  matches any changed file owner to its isolation journal, then clears the
  snapshot before removing the anchor namespace. Preflight refuses a changed
  directory or an unjournaled file-owner change before retirement starts;
  the file's held write guard rechecks an unjournaled owner before unlink.
  Restart after one file retired and ordinary two-file retirement pass on ext4
  and fresh local Btrfs, alongside 115 normal store tests and strict workspace
  Clippy.
  This earlier retirement path requires the recorded root and directories to
  remain unchanged; the later directory-isolation journal below handles its
  owner/mode changes. User-visible path and metadata changes still need
  replayable restoration. Detached owner-isolated files remain fenced.
  An owner-first root capture path now records its private selection before
  the first file, rechecks each prepared file under a write guard, and records
  the original owner before freezing access and changing UID/GID. It creates
  the hard-link anchor only after the source is private; a crash at the
  intermediate points leaves no user-owned immutable link. Root replay
  reconstructs the original-owner snapshot from file journals, and root
  retirement restores the user owners. Prepared captures with no owner
  journal can be canceled without publishing an anchor; missing/moved sources
  fail closed. ACL-bearing files are refused before the private transition.
  Per-file interruption, root reopen/retirement, prepared cancellation, ACL
  refusal, 116 normal store tests, and strict Clippy pass; the privileged
  cases pass on ext4 and fresh local Btrfs. The older ordinary guarded-capture
  path remains available for non-enrollment use and must not be selected for
  a private guarded mount. A separate directory-isolation record now binds the
  original lower-ownership snapshot to the selected private UID/GID before any
  directory mode or owner change. The root and every captured child directory
  transition to private `0700` ownership, replaying original, mode-restricted,
  and fully private intermediate states. Root retirement restores their
  original owner and mode after all frozen file anchors retire, and replays an
  interrupted restoration. Access/default ACLs and file capabilities on
  directories fail closed before isolation. Three privileged probes cover
  interrupted isolation/retirement, retained ordinary-user directory
  descriptors, and default-ACL refusal on ext4 and fresh local Btrfs; 116
  normal store tests and strict workspace Clippy pass. First-mount admission
  now checks every captured lower path's identity and compares each directory's
  complete entry set with the plan before namespace replay; directory isolation
  checks the same inventory before and after changing ownership. Only a marked
  app-owned Git catalog is excluded. An unplanned entry fails before an
  isolation record or mount claim is created. Normal replacement/unknown-entry
  cases pass locally; privileged first-mount and isolator refusal pass on ext4
  and fresh local Btrfs, alongside 117 normal store tests and strict workspace
  Clippy.
  Remount now reconstructs the visible name and inode map from durable FUSE
  records, then compares every lower directory's complete entry set and every
  named inode with that map before publishing the mount. An unrecorded root or
  dynamic-directory file refuses recovery; legitimate replacement and
  populated-directory rename with new descendants still recover. These
  privileged remount probes pass on ext4 and fresh local Btrfs, alongside 117
  normal store tests and strict workspace Clippy. Before any remount replay,
  a bounded descriptor walk now rejects lower inodes absent from the captured
  plan, durable file/directory records, and pending create/move/replace/remove
  intents; it also rejects extra hard-link aliases. A normal pending populated-
  directory rename probe proves an unknown file is refused while the intent
  and lower source remain unchanged, then accepts all three legitimate rename
  crash states. Pending create and replacement states also pass. The guarded
  remount probe and 117 normal store tests pass on ext4; remount, replace, and
  populated rename probes pass on fresh local Btrfs; strict Clippy passes.
  Pre-replay now also checks each lower path against its recorded native inode,
  permitting alternate paths and rebased descendants only when granted by a
  durable pending namespace intent. Moving a recorded inode to an ungranted
  path refuses recovery before replay can mutate the lower tree; post-replay
  inventory still enforces the exact final namespace before mount publication.
  Normal create/remove/replace/rename crash states, ext4 remount, and fresh
  local Btrfs remount/replace/rename probes pass, alongside 117 normal store
  tests and strict workspace Clippy. A detached named file now restores its
  original UID/GID from the durable owner journal before a writable view handle
  returns; replay also handles a crash after detach and before owner restore.
  The focused privileged root test passes on ext4 and fresh local Btrfs, and
  117 normal store tests plus strict workspace Clippy pass. Retirement now
  resolves a frozen captured file's current name from its completed FUSE
  namespace record and rebinds its capture journal before unlinking the anchor.
  It refuses unfinished or malformed namespace state before retirement begins.
  An ordinary-user same-directory rename, remount, and final owner/access
  restoration pass on ext4 and fresh local Btrfs; the retained anchor remains
  byte-exact through refused retirements. Captured-directory retirement now
  resolves completed FUSE move records for every planned directory and restores
  their original owner and mode at the verified current inode. A root-level
  directory move with a nested frozen file survives remount and retirement on
  ext4 and fresh local Btrfs; malformed records, a replaced lower directory,
  and an interrupted owner-before-mode restoration fail or replay as expected.
  Retirement now also accepts a completed FUSE removal or replacement of an
  empty captured directory. Before dropping its original-owner obligation, a
  bounded descriptor walk proves that the removed inode has no remaining name
  in the lower tree; a replacement source directory still restores its owner
  and mode at the verified target path. An ordinary-user rmdir/replace,
  remount, and final retirement pass on ext4 and fresh local Btrfs. A detached
  file whose owner journal survived a crash now restores its original owner at
  a verified moved view name, or clears that journal after unlink/replacement
  only when a bounded scan proves the original inode has no lower-tree name.
  A surviving moved name refuses journal cleanup. Ordinary-user remove,
  replace, move, remount, and final retirement pass on ext4 and fresh local
  Btrfs; 118 normal store tests and strict workspace Clippy pass. Guarded
  enrollment still needs protected mutable-view metadata and the complete
  privileged mount gate.
  A fresh default-atime Btrfs run of all 18 privileged FUSE probes exposed
  internal remount inventory reads advancing a user-set directory atime.
  Pinned source reads now request `O_NOATIME` where permitted, leaving the
  visible timestamp intact; the passthrough probe also keeps its disposable
  parent on the provisioned filesystem. All 18 guarded-view probes pass on
  ext4 and fresh default-atime Btrfs after these corrections, alongside 118
  normal store tests and strict workspace Clippy. Signed view-metadata
  recovery and guarded enrollment remain open.
  Concurrent inventory walks now open independent, identity-checked directory
  descriptors instead of duplicating one shared read offset. A regression
  interleaves two streams over the same directory and proves that both see all
  names. The 119 normal store tests, strict workspace Clippy, and all 18
  privileged FUSE probes pass on ext4 and fresh default-atime Btrfs. Signed
  metadata recovery and guarded enrollment remain open.
  A stopped claimed view can now export a versioned, verified snapshot of its
  current raw-byte namespace, native inode identities, virtual root/directory
  modes, visible uid/gid, file modes and lengths, and access/modification
  timestamps. It refuses a live mount or unrecorded lower entry and rebuilds
  the same visible names, modes, and inode identities after control-database
  reopen. The focused privileged probe passes on local ext4 and disposable
  Btrfs; all 18 guarded FUSE probes on ext4, 119 normal store tests, and
  strict workspace Clippy pass. This remains local input only: capture the
  snapshot's current file bytes into immutable anchors, include its metadata
  in a signed owner revision, prove seed-only recovery, and only then enable
  guarded node enrollment.
  A stopped claimed view can now capture an edited or newly created visible
  file into a second guarded hard-link anchor. Its per-inode record is durable
  before the link is made; remount verifies or resumes the capture and detaches
  that new anchor before a later write, including after rename. A privileged
  regression recaptures the same inode twice and captures a view-created file;
  it passes on local ext4 and disposable Btrfs. All 18 existing guarded FUSE
  probes, 119 normal store tests, and strict workspace Clippy also pass.
  The local anchors still need an atomic association with signed owner
  revisions, seed-only recovery of the mutable view, and coordinated
  retirement of the per-inode guard records and their anchors before guarded
  enrollment or Git stage/checkout may select this backend.
  File-anchor retirement now rejects a guard still needed by a claimed view;
  it removes the matching per-inode record only after physical anchor cleanup.
  Root-anchor retirement waits for all such records to clear. The focused
  privileged test covers active-anchor refusal, superseded-anchor cleanup,
  and final root cleanup on local ext4 and disposable Btrfs. Node-level
  reachability and signed-revision GC still need to drive this ordering.
  A single stopped-view capture now returns versioned visible metadata plus
  one immutable, byte-hashed, sparse-extent-checked locator per file. It reuses
  an original root anchor only while that file's root journal says the working
  inode is frozen; an edited inode may retain the same native ID, so identity
  alone is insufficient. Edited and created files use durable secondary guards.
  The aggregate verifies after canonical encoding and control-DB reopen, and
  its focused nested-path regression passes on ext4 and disposable Btrfs.
  This remains local capture input: the node still must bind its metadata and
  file bytes into a signed owner revision, recover the mutable view from a
  seed, and drive reachability-based cleanup before guarded enrollment.
  The store now durably prepares a stopped-view revision attempt before any
  file recapture. Prepared attempts block remount; daemon claim recovery
  finishes them under the stopped-view fence, including after one file was
  frozen and the control DB reopened. Both preparation and publication retries
  use the original verified anchors even after later view edits or remount.
  Root and per-file retirement honor the attempt's anchor pins until the owner
  explicitly releases the intent. The focused privileged test passes on ext4
  and a fresh disposable Btrfs image. Node revision creation still needs to
  own this attempt ID, transfer its pins into signed-revision retention, and
  release the local intent only after that transfer commits.
  The stopped-view metadata now validates raw paths, complete parent
  directories, source filesystem identity, timestamp bounds, and hard-link
  alias consistency before an attempt is retained or published. A normal
  unit test covers malformed metadata and a non-UTF-8 filename; the privileged
  stopped-capture probe passes with that validation. The signed private
  revision format still needs to carry these raw paths, ownership, modes,
  atimes, and file anchors losslessly, then restore them from a seed.
  The node now checks that its live guarded mount set exactly matches the
  durable claims. Its stopped-capture operation stops the owned FUSE view,
  publishes a revision-ID-bound capture, and remounts only after publication;
  an error leaves the missing mount visible to the daemon health check. The
  node-level privileged probe covers an edited file, anchor bytes, remount,
  and eventual anchor cleanup on ext4 and disposable Btrfs. This operation
  still needs to be called from the signed revision path after the lossless
  private metadata and recovery format are implemented.
  A version-6 private metadata shape now removes local anchor and inode IDs
  while preserving raw Unix paths, visible uid/gid, modes, atimes, mtimes,
  directory lengths, hard-link groups, and sparse sector geometry. It builds
  from a verified stopped capture, validates decoded bounds and path topology,
  and round-trips a non-UTF-8 hard-link fixture. The node-level privileged
  capture probe constructs it from an edited view. Revision signing, seed
  restore, and recovered-anchor pin transfer still need to consume this shape.
  Format-6 restore now dispatches through the signed `UserRevision` restore
  path: it validates the private metadata before creating names, rebuilds raw
  filenames, sparse bytes and hard-link aliases from signed sectors, and
  reapplies uid/gid, mode, atime and mtime to restored inodes. A signed
  revision fixture exercises durable restore publication and root-metadata
  reapplication; the snapshot compatibility group passes. Git descriptor
  inspection treats a validated guarded revision as non-Git. Guarded revision
  scheduling, reanchoring after seed recovery, view
  reconstruction (including virtual directory lengths), and GC remain open.
  A guarded signing helper now encodes published stopped-view anchors into
  signed format-5 `UserRevision` sectors with format-6 private metadata. One
  SQL transaction publishes the revision, sector recipes and a local revision
  capture map while deleting the stopped-capture attempt by compare-and-delete.
  Both root and file retirement honor the transferred pins. A privileged node
  probe signs, retries, restores and releases a captured edit on ext4 and
  disposable Btrfs; a database test proves stale-intent rollback. The normal
  protected-root backend binding still selects reflink, so node backup jobs
  do not yet invoke guarded signing. Recovered guarded anchors still need
  durable replay and safe release before guarded enrollment.
  Guarded revision GC now waits for the signed revision and every local-sector
  recipe to release its anchors, then atomically transfers the local capture
  map to a durable retirement record. Restart reconciliation retires secondary
  file guards before the root and leaves the record pending while a claimed
  view, another revision, or an unavailable source prevents cleanup. The
  privileged node lifecycle probe exercises this handoff on ext4 and Btrfs.
  Replay now rescans surviving sector recipes before physical cleanup, so a
  recipe retained or restored after the map transfer still pins its source;
  the reopened-control lifecycle probe checks that cleanup waits for its
  removal.
  Restored format-6 revisions can now reanchor their signed data sectors
  through durable per-file reflinks on a capable restore filesystem. Versioned
  local plans and sealed manifests preserve raw Unix filenames; the Btrfs
  fixture covers sparse bytes, a hard-link alias, interruption after capture,
  control-DB reopen, retry, and reachability-based anchor retirement. A
  signed-byte mismatch now discards only the unpublished capture intent, so
  correcting the restored source permits a fresh plan; the Btrfs fixture
  checks a nonzero byte in a signed sparse gap before a successful retry. This
  does not yet reconstruct the guarded FUSE view or reanchor on a non-reflink
  filesystem; those remain enrollment and recovery gates. Linux local plans,
  anchor-area hints, restore jobs, protected-root and volume records now encode
  raw paths without changing historical UTF-8 record bytes. The Btrfs fixtures
  pass with non-UTF-8 mountpoint, parent, target and file names across recovery,
  reanchor, node reopen and guarded mount supervision. The JSON local control
  codec now keeps UTF-8 paths as strings and carries raw Unix path bytes in a
  tagged hex form. CDDL-validated request, path-list and status round trips
  pass, including rejection of malformed hex. A provisioned local Btrfs
  process test now passes a non-UTF-8 root through `mutualbackup root add`,
  then reads its exact path back from the daemon over the control socket.
  The same process gate now initializes Git under that root, stages raw-name
  regular files and symlinks, reopens the daemon, commits, and restores their
  exact bytes and link target, then pushes and fetches through a local bare
  Git repository. Git stage/fetch intents and its native object map now encode
  those local paths losslessly; historical UTF-8 Postcard bytes remain unchanged.
  The privileged node fixture now feeds signed format-6 sectors to a fresh
  same-seed node on disposable Btrfs and runs the production recovery job
  through restore, reanchor, root registration, and reopen/retry. That local
  path passes; at that stage it did not cover full network seed-only recovery
  or guarded-view reconstruction without reflinks.
  Guarded-root removal now has a `root remove-guarded` control path. For an
  in-place root, it journals a root/anchor/handoff-bound intent before stopping FUSE,
  refuses retained Git, signed-revision, checkpoint, recipe, and in-flight
  pins, then detaches live files, retires the claim and original anchor, returns
  the original directory name and visible metadata, and atomically removes the
  protected-root/backend/dirty records and handoff journals. Startup excludes
  only validated pending releases from mount recovery and finishes them before
  serving the node. The privileged node probe covers a live ordinary-user edit
  and restart after each release boundary on ext4 and disposable Btrfs; the
  request/response schema and CLI command are wired locally. A child-process
  probe now persists a release intent while its FUSE view is still mounted,
  is killed, and proves startup detaches the dead mount and returns the edited
  bytes on ext4 and disposable Btrfs. A separate-lower root now uses its own
  parent-identity-bound release journal: after the same stopped-view detach and
  anchor retirement, it moves the private lower directory into the original
  view path without copying payloads, then restores the checked visible
  metadata. Its privileged probe passes on ext4 and disposable Btrfs for
  each release boundary, distinct lower/view parent directories, a missing
  placeholder after its name marker, and foreign replacements both before and
  after that marker that fail closed until the intended name can be restored.
  The same ext4/Btrfs probe kills a child with a live separate-view
  FUSE mount and a durable release intent, then verifies that startup returns
  its edited and newly created files at the view path. Guarded Git pin
  integration remains open before broader Git operations can select this
  backend. Both release layouts now require a matching durable root-retirement
  marker and no remaining root ownership claims before the directory name is
  returned; a missing capture plan alone is insufficient. A separate-view
  interruption test removes the plan before retirement, confirms startup fails
  closed with the lower tree intact, then restores the plan and completes
  replay. That test and the in-place release fixture pass on ext4 and fresh
  local Btrfs.
  Guarded root capture now uses a version-2 plan and version-3 sealed manifest
  when an entry has raw Unix path bytes; version-1/2 UTF-8 records keep their
  prior bytes. Directory claims, lower ownership, freeze journals, namespace
  records, captured entries, and anchor locators carry those raw names through
  capture and remount. A normal test verifies raw nested inventory and rejects
  it under the old plan version; another checks historical UTF-8 plan bytes.
  The privileged node mount/restart test now includes a raw directory and
  nested raw filename, edits it through FUSE while preserving its original
  anchor, signs its guarded stopped capture, restores its exact bytes on ext4
  and Btrfs, and exercises same-seed recovery/reanchor on Btrfs.
  That initial Btrfs-only recovery fixture did not cover a non-reflink
  filesystem.
  Recovery now binds signed format-6 raw paths and virtual attributes to the
  restored tree's local inodes before retaining new anchors. It rejects extra
  names, changed lengths, and hard-link aliases outside the signed namespace;
  a directory-only revision is bound even with no data sectors. The binding
  carries signed directory lengths for later FUSE reconstruction. A guarded
  mount can now accept those locally rebound virtual attributes, validate
  every entry against its sealed capture, and persist root/entry ownership,
  root/directory modes, and directory lengths across remount; a local
  disposable-Btrfs FUSE test covers rejection before publication, exact file
  bytes, chmod precedence, remount, and retirement cleanup. The privileged
  node fixture now decodes the actual signed format-6 sectors, binds them to
  newly restored local inodes, and mounts the resulting guarded view with its
  raw names and virtual directory length. That path passes locally on ext4
  and disposable Btrfs, including remount. Btrfs recovery exposed a signed
  atime mismatch after capture. The mount now persists a per-inode first-mount
  time baseline and presents signed atime/mtime until the lower time changes;
  a changed directory mtime remains visible after remount. Focused privileged
  ext4/Btrfs probes cover signed times, a changed directory mtime, and
  baseline cleanup on retirement. Explicit FUSE timestamp setters now record
  durable per-inode dirty bits before changing the lower inode, so setting a
  time back to its original lower value cannot resurrect the signed time after
  remount; the ext4/Btrfs probes cover that sequence and dirty-record cleanup.
  A recovered directory presents its signed length until its namespace changes;
  create, remove, and rename then durably invalidate that length and show the
  live lower-directory length across remount. The privileged ext4/Btrfs probe
  covers create/remove, remount, and marker retirement.
  Before a published format-6 recovery job registers its protected root, it
  now rebinds the entire restored namespace to the signed paths and local
  inode identities and verifies every file and sparse gap against signed
  sectors. An interrupted-publication Btrfs probe adds an unexpected file and
  changes a file without changing its length; both retries refuse root
  registration, then completion succeeds after the bytes are restored;
  the focused Btrfs probe and strict Clippy pass on this source. The complete
  normal node suite passed before the final content-verification addition.
  A versioned local handoff now journals the restored inode and a private
  placeholder before moving the restored target to a hidden lower path.
  Replay finishes either rename boundary, leaves an unbound crash-time
  placeholder untouched, and rejects a foreign lower inode. A raw-name store
  probe passes on ext4 and disposable Btrfs; the privileged node fixture now
  uses this handoff to mount its signed restored tree at the original target
  path on both filesystems. A version-4 protected-root registration now binds
  that public mount to its supervised claim and private lower inode, rather
  than FUSE's transient filesystem identity. After node reopen, the guarded
  source backend routes a new revision through stopped-view capture and signed
  format-6 sectors; focused ext4/Btrfs tests restore the exact CRLF/NUL bytes.
  Git file operations remain gated for this backend. The production format-6
  recovery job now journals and resumes the private-lower handoff, persists a
  signed-view mount intent before hard-link capture, verifies the captured
  anchors against signed sectors, and registers the supervised format-4 root
  only after the mount claim and virtual metadata agree. Recovery supersession
  cannot discard an unfinished private-lower handoff. A privileged disposable-
  Btrfs fixture exercises publication tampering, interruption and node reopen
  after the handoff and mount intent, completed mount reopen, and exact file
  bytes. Production format-6 jobs now verify the restored staging tree before
  publication, then install signed data-sector recipes from the sealed guarded
  root capture rather than a preliminary reflink. Privileged ext4 and Btrfs
  runs pass the same seed-only restore, handoff, mount, restart, and exact-byte
  checks, including restarts after the durable mount intent and captured
  sector recipes. Both runs edit the recovered FUSE view, reopen the node, and
  confirm that the signed sector recipes still reproduce the pre-edit bytes;
  the Btrfs run also migrates an older reflink-backed capture into durable
  retirement. A five-member local memory-guild test now loses the guarded
  owner's data directory and source tree, reconstructs its signed format-6
  sectors from the remaining members, and restores an ordinary-user-readable
  guarded view from the seed on ext4 and disposable Btrfs. This closes the
  reconstructed-shard integration check; a provisioned P2P network gate,
  guarded removal/GC, and broader FUSE failure paths remain open before
  enrollment. The general revision-anchor retirement path now waits for the
  signed revision and every local-sector recipe referencing its anchor; replay
  rechecks recipe pins before physical deletion. GC builds this recipe-pin set
  once after sector cleanup for an anchor batch. A privileged Btrfs regression
  keeps an old anchor through retirement replay while a separate recipe pins
  it, then collects it after that pin is removed. Guarded-root claim retirement
  and data-preserving removal remain open.
  Node enrollment now persists a versioned plan and placeholder inode before
  changing lower ownership, then replays private capture, directory isolation,
  mount claim, and protected-root registration on restart. The initial root is
  marked dirty for its first signed backup. Privileged local replay tests cover
  interruption before capture, after isolation, and after mount claim, plus a
  replaced-placeholder refusal before mutation on ext4 and disposable Btrfs.
  The existing guarded signed-backup fixture now uses the production enrollment
  API and passes on both filesystems. The 325 normal node tests, local-control
  raw-path schema test, CLI help check, and strict workspace Clippy pass. This
  enabled the separate lower/view path. At that stage original-path migration,
  data-preserving removal and claim retirement, Git operations through the
  guarded backend, and the complete guarded failure gate remain open.
  A stopped-view release primitive now walks every live file through its
  replayable writable-open detach journal and requires a single lower hard
  link before returning. A privileged ext4 and disposable-Btrfs regression
  renames a frozen file, creates a second file, retries release preparation,
  and proves that editing the lower working inode leaves the relocated anchor
  byte-exact; ordinary anchor retirement then succeeds. Root removal still
  needs a durable name handoff, visible metadata restoration, revision/Git pin
  checks, and protected-root record retirement before this primitive can be
  exposed as a command.
  In-place enrollment now captures the original root and entry presentation
  metadata before a versioned handoff moves the target to a private lower
  name. A second durable enrollment intent binds the hidden lower plan and
  placeholder inode before capture, isolation, virtual-metadata mount, and
  dirty protected-root registration. Restart replays the handoff, plan, and
  mount boundaries; privileged ext4 and disposable-Btrfs tests pass those
  phases, ordinary-user view access versus private-lower denial, a changed
  private file before capture that fails closed, and a signed backup/restore
  round-trip with exact CRLF/NUL bytes. The source-only snapshot test preserves
  raw names and rejects a changed entry. Mixed-owner trees,
  broader fault injection, removal, and the complete guarded gate remain open.
  The in-place handoff now has a reverse-name primitive for removal: a durable
  release marker fences enrollment replay, the exact retired mount claim must
  bind the lower and placeholder, and interruption after placeholder deletion
  can replay the no-replace return of the private directory. A post-detach
  stopped-view snapshot is now retained before claim retirement and fences
  remount. The stopped-view path applies durable virtual presentation metadata,
  and replayable restoration checks the full raw-name namespace and inode IDs,
  then restores file and directory owner/mode/times with the root exposed last.
  The ext4 and Btrfs release probe covers nested entries, an unrecorded-file
  refusal, repeated restore, and anchor isolation after an edit. Removal still
  needs revision/Git pin checks, protected-root record retirement, release and
  handoff-record cleanup, startup reconciliation, and the remaining ACL/xattr
  fidelity gate before exposing a command.
  A read-only node removal preflight now refuses a Git repository, unfinished
  capture/backup/restore/GC work, a guarded revision-capture pin, and a local
  sector recipe using the root anchor before any view mutation. Claim retirement
  repeats its revision-pin check. Privileged ext4 and Btrfs probes confirm an
  unbacked root passes while a Git record and a signed guarded revision block
  removal. The preflight is not yet a removal command; retained revision and
  Git anchor ownership still require end-to-end retirement and replay gates.
  Broader FUSE failure paths and the full guarded-enrollment gate remain open.
  Keep Git staging and checkout gated until the complete privileged probe
  passes. See
  [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
  and [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html).

## Milestone 4 follow-up source review — closed 2026-09-15

Source review of `197c6b0..1b9f99e` found one remaining completion blocker
in M4-37's capacity correction. Per-holder serialization removes the explicit
probe burst, but receiving a response does not guarantee that the holder has
released its request worker. No remaining blocker was identified in M4-38's
matching READY publication retry correction. That review reopened Milestone 4;
the earlier passing gates remained evidence for their exercised cases. The
review ran no builds, tests, or runtime probes. Commit `193f67e` resolves
M4-39, and the local correction gate below passed.

- [x] **M4-39 / P2 — Release holder capacity before exposing a completed response.**
  The blocking worker retains its inbound permit while enqueueing
  `InboundResult` (`crates/mb-node/src/network/p2p.rs:4432`, `p2p.rs:4434`).
  The event loop can send that response before the worker resumes and drops
  the permit (`p2p.rs:2844`, `p2p.rs:2852`). Consequently, even the new
  sequential discovery loop (`p2p.rs:6206`) can receive retryable Busy for its
  next probe when the holder has one available worker (`p2p.rs:4394`). With
  A/B/C holding assigned indices 0/1/2, D/E offline, and emergency indices 3
  on B and 4 on C, pause B's worker after enqueueing the absent-index-2
  response. B's next probe for its existing index 3 is rejected while that
  worker still owns the permit. Inventory discards the error without retry
  (`p2p.rs:6223`); even if it discovers C's index 4, the known layout loses
  indices 2 and 4 together with C and persists Emergency instead of the
  actual Degraded status (`p2p.rs:6365`, `p2p.rs:6379`). Release or transfer
  permit ownership so capacity is available before the response becomes
  observable, preserving bounded response handling, or handle retryable
  capacity outcomes with a bounded policy before finalizing inventory. Add
  a deterministic regression that holds the preceding worker after its
  result is queued, then exercises the next sequential probe with one
  available worker and verifies complete discovery and durable Degraded
  status after a read-only audit and reopen. The constrained-permit regression
  at review time (`p2p.rs:11767`) did not force this response/permit handoff.
- [x] **Run the Milestone 4 correction gate after M4-39.**
  On 2026-09-15, commit `193f67e` passed formatting, locked all-target
  workspace tests, warning-free locked all-target workspace Clippy, and Docker
  controller safety. A freshly provisioned disposable 2 GiB Btrfs filesystem
  with `user_subvol_rm_allowed` passed the complete
  `scripts/reflink-acceptance.sh` gate, including capture and recovery
  reconciliation, shared-filesystem WAL headroom, repeated multi-owner QUIC
  backup, five-daemon seed/DHT recovery after source and holder loss, and
  isolated direct/DCUtR/relay paths. The deterministic handoff regression
  leaves one request permit available on each reachable remote holder, holds
  the first completed workers after their results are queued, and verifies
  complete discovery with durable Degraded status through reopen. All
  compilation and execution were local; no remote compilation server was used.

## Milestone 4 follow-up correction record — M4-37 and M4-38

Source review of `fb73787..546a1b9` found two completion blockers in the
latest audit and physical-admission changes. The retired-volume correction
has no remaining blocker identified in this review. Commits `736bf20` and
`fea97b1` were recorded as resolving the two findings, and the local correction
gate below passed. The later source review recorded M4-39 for the remaining
response/permit handoff; commit `193f67e` and the gate above close it. The
review itself ran no builds, tests, or runtime probes.

- [x] **M4-37 / P2 — Avoid overloading holders during emergency-copy discovery.**
  The new emergency inventory launches four probes per remote holder together
  (`crates/mb-node/src/network/p2p.rs:6193`, `p2p.rs:6212`). A supported holder
  with `max_connections = 1` immediately rejects overlapping requests with
  retryable `Busy` (`p2p.rs:4394`; existing worker-limit test at `p2p.rs:11013`).
  Audit treats those responses as missing copies without retrying
  (`p2p.rs:6214`, `p2p.rs:7415`). With D/E offline, A/B/C holding assigned
  indices 0/1/2, and emergency indices 3 on B and 4 on C, the actual layout
  survives another holder loss. If absent-index probes occupy B/C's workers
  when their emergency-copy probes arrive, the audit discovers only three
  indices and persists Emergency instead of Degraded (`p2p.rs:6349`,
  `p2p.rs:6369`). Serialize discovery per holder or handle retryable capacity
  responses with bounded retries before finalizing inventory. Add a regression
  with low-capacity holders and overlapping probes, checking complete location
  discovery and correct durable status after a read-only audit and reopen.
- [x] **M4-38 / P2 — Allow matching READY publication retries near capacity.**
  The receipt branch now requires physical space for another complete sector
  plus WAL backfill before validating the existing object
  (`crates/mb-node/src/volume.rs:711`). Matching READY bytes and acknowledgement
  already complete without a parity write in
  `crates/mb-store/src/database.rs:1505`. A publish interrupted after durable
  object/receipt publication but before its peer-operation result commits is
  reexecuted on retry (`crates/mb-node/src/network.rs:695`, `network.rs:708`).
  If remaining space above headroom is below the new-sector reservation, the
  retry now returns CapacityExceeded even though the sector is already stored
  and enough space remains for its small control completion records. Validate
  the exact existing payload, metadata, and acknowledgement before treating a
  retry as requiring growth; retain admission for actual writes and reject
  conflicting retries. Cover interruption, reopen, and retry at the physical
  boundary through the peer publication path, including durable completion
  and unchanged parity allocation. The current boundary regression
  (`volume.rs:2479`) only exercises admission of a new object.
- [x] **Run the Milestone 4 correction gate after M4-37 and M4-38.**
  On 2026-09-15, the corrected source tree passed formatting, locked all-target
  workspace tests, warning-free locked all-target workspace Clippy, and Docker
  controller safety. A locally provisioned disposable 2 GiB Btrfs filesystem
  passed the complete `scripts/reflink-acceptance.sh` gate, including capture
  and recovery reconciliation, shared-filesystem WAL headroom, repeated
  multi-owner QUIC backup, five-daemon seed/DHT recovery after source and
  holder loss, and isolated direct/DCUtR/relay paths. Focused regressions cover
  one available request worker per remote audit holder, complete location
  discovery with durable Degraded status, and interrupted READY publication
  replay at constrained headroom without parity growth. All compilation and
  execution were local; no remote compilation server was used.

## Milestone 4 follow-up correction record — M4-34 through M4-36

Source review of `668324f..d12f5fb` found three remaining completion blockers
in the corrections to M4-29, M4-32, and M4-33. Commits `9081266`, `7c58281`,
and `89c6569` were recorded as resolving them, and the local correction gate
below passed. The latest source review above reopens milestone completion.
Earlier passing gates cover their exercised cases, but not the schedules
below. This review ran no builds, tests, or runtime probes.

- [x] **M4-34 / P2 — Reserve WAL backlog even when automatic checkpointing stalls.**
  Setting `wal_autocheckpoint = 1` (`crates/mb-store/src/database.rs:2266`)
  requests a PASSIVE checkpoint; it does not guarantee that backfill completes.
  The pinned SQLCipher source caps backfill at active readers and its automatic
  hook ignores checkpoint errors. Peer reads use connections independent of
  the writer lock (`crates/mb-node/src/network.rs:617`,
  `crates/mb-node/src/node.rs:505`). A held read snapshot can therefore leave
  MiBs of new pages in WAL across many writes. After it finishes, the next
  ordinary write can pass admission with free space equal to headroom plus
  400 KiB, then checkpoint those MiBs into the main database. Admission still
  reserves only the current object and fixed overhead
  (`crates/mb-node/src/volume.rs:710`,
  `volume.rs:1343`). Reopening a large WAL left by an interrupted previous
  version also does not flush it merely by changing the threshold. Reserve
  outstanding main-file growth or coordinate readers and verify checkpoint
  completion before relying on a bounded reserve. Cover held readers and
  upgrade with an uncheckpointed WAL at the physical headroom boundary,
  including control storage on the shared filesystem. The new database test
  (`database.rs:3516`) uses fresh stores with one connection per database.
- [x] **M4-35 / P2 — Settle pending intents and stale receipts before empty drain retirement.**
  `settle_empty_volume_cleanup` clears only `volume-copy-cleanup`
  (`crates/mb-node/src/volume.rs:1067`). An emergency repair interrupted at
  `WriteIntentStored` leaves a durable marker and intent without a payload
  (`crates/mb-node/src/node.rs:2465`, `volume.rs:764`). Startup preserves the
  intent when the object is absent (`volume.rs:795`). Draining this empty
  volume then marks it Retired and closes its store (`volume.rs:952`). Later
  emergency cleanup/GC requires the intent's volume, cannot access the closed
  store, and never retires the marker/proof or intent (`volume.rs:616`,
  `node.rs:2505`). A receipt left by interruption after `GarbageObjectRemoved`
  has the analogous problem. Reconcile all durable location evidence against
  the verified-empty source before declaring it removable, preserving valid
  destination receipts. Also handle cleanup obligations already attached to
  Retired volumes by the previous implementation. Extend the emergency
  interruption regression (`node.rs:5818`) through reopen, drain, cleanup,
  disk removal, and repeated reopen; cover interrupted GC followed by drain
  and assert that intents, receipts, markers/proofs, cleanup records, and
  garbage candidates converge.
- [x] **M4-36 / P2 — Report protection from all verified emergency-copy locations.**
  Discovery stops at the first valid alternate for each missing shard
  (`crates/mb-node/src/network/p2p.rs:6197`), but repair can create another
  copy even when it already found one (`p2p.rs:6265`). With D/E absent and
  surviving node IDs A < B < C holding indices 0/1/2, the first repair stores
  3 on A and 4 on B. The second stores another 3 on C and another 4 on A.
  The resulting layout survives any further single host loss, yet a later
  audit with repair disabled finds both emergency indices first on A and
  ignores their other copies. Its incomplete location sets report that losing
  A leaves only two indices and persist Emergency instead of Degraded
  (`p2p.rs:6318`, `p2p.rs:6338`). Collect all verified locations, or an
  equivalent complete inventory, for placement and durable protection status.
  Cover repeated repairs followed by read-only audits and reopen, as well as
  corrected older concentrated layouts. The new outage regression
  (`p2p.rs:11702`) reconstructs from all copies collected directly from nodes;
  it does not check that a later audit discovers the same protection.

- [x] **Run the Milestone 4 correction gate after M4-34 through M4-36.**
  On 2026-09-15, the exact corrected source tree passed formatting, locked
  all-target workspace tests, warning-free locked all-target workspace Clippy,
  and Docker-controller safety. A locally provisioned disposable 2 GiB Btrfs
  filesystem passed the complete `scripts/reflink-acceptance.sh` gate. That
  gate included the held-reader parity/control WAL headroom boundary, capture
  and recovery reconciliation, repeated multi-owner QUIC backup, five-daemon
  seed/DHT recovery after source and holder loss, and isolated direct/DCUtR/
  relay network paths. Focused regressions also cover an old-threshold WAL
  reopen, pending intent and stale receipt retirement, already-Retired cleanup,
  repeated emergency repairs, complete copy discovery, durable audit status,
  and reconstruction after every surviving-host loss. All compilation and
  execution were local; no remote compilation server was used.

## Milestone 4 correction review — prior correction record

Source review of `8411f7d..2da3e82` found the blockers below in the correction
and its Milestone 4 integration. M4-29 also checks the existing emergency
placement against the milestone's outage-layout requirement. Earlier passing
gates remain historical evidence for their exercised cases; they do not close
these failure schedules. This review ran no builds, tests, or runtime probes.
Commits `27cb1b2`, `a265cc1`, and `04875a9` were recorded as resolving M4-28
through M4-33, and the local correction gate below passed. The follow-up above
supersedes that closure for the remaining M4-29, M4-32, and M4-33 schedules;
the checked entries below preserve the prior correction record.

- [x] **M4-28 / P1 — Resume legacy parity rekey after manifest publication.**
  The new manifest-present initialization branch opens only with the wrapped
  random key (`crates/mb-node/src/volume.rs:1124`). Legacy migration publishes
  that manifest before rekeying the existing database (`volume.rs:1151`,
  `volume.rs:1171`), and the control registry is saved only after initialization
  returns (`volume.rs:192`). An interruption between manifest publication and
  rekey leaves a valid old-key database and no registry. Restart now fails in
  initialization before reaching the legacy-key fallback at `volume.rs:1211`,
  preventing node startup (`crates/mb-node/src/node.rs:596`). Preserve recovery
  through both authenticated key states without recreating lost established
  databases. Cover a nonempty legacy database, interruption before/after rekey
  and registry publication, and successful reopen with unchanged objects.
- [x] **M4-29 / P1 — Place emergency copies across surviving failure domains.**
  Each missing shard starts with the same sorted alternate roster and stops
  at the first successful store (`crates/mb-node/src/network/p2p.rs:6254`,
  `p2p.rs:6292`). With holders D/E unavailable and A/B/C holding indices 0/1/2,
  both reconstructed indices 3/4 can land on lowest-ID A. The audit then
  reports Degraded by counting distinct shard indices (`p2p.rs:6308`), but
  losing A leaves only indices 1/2. Distributing the two copies across A/B
  would preserve three after any further single surviving-host loss. Track
  actual copy locations and failure domains during placement and protection
  reporting, consistent with the fixed-profile outage requirement. Cover two
  absent holders, emergency repair, loss of each surviving host in turn, and
  actual reconstruction; deleting only individual sectors while the emergency
  holder stays online (`p2p.rs:11536`) does not exercise this case.
- [x] **M4-30 / P2 — Include pending write destinations in garbage collection.**
  `remove_unreachable` checks receipts, copy-cleanup obligations, and Draining
  state, but ignores `volume-write-intent` (`crates/mb-node/src/volume.rs:595`).
  Emergency repair can commit its marker and payload, then stop before receipt
  publication (`volume.rs:747`). If that volume is absent after restart,
  reconciliation preserves its intent, but healthy-group cleanup reports
  success and deletes the marker/proof (`crates/mb-node/src/node.rs:2513`).
  On volume return, reconciliation recreates the receipt (`volume.rs:781`),
  leaving information-shard bytes without emergency classification or future
  volume GC. Include pending destinations in cleanup obligations, and retire
  their intents only when collection converges. Cover payload-before-receipt
  interruption, absent volume, cleanup, return, and repeated reopen.
- [x] **M4-31 / P2 — Preserve the old destination before replacing a write intent.**
  Publication overwrites the single object-keyed intent without retaining its
  previous destination (`crates/mb-node/src/volume.rs:729`). `store_repair`
  records an old cleanup volume only when a receipt exists (`volume.rs:651`).
  If A commits a payload but loses power before its receipt, retry with A absent
  can publish on B and replace/delete A's only location evidence. Later GC
  collects B and forgets A's copy permanently; fixing M4-30 alone cannot recover
  a discarded UUID. Preserve prior pending destinations before retargeting a
  repair or migration write. Cover an interrupted destination commit, retry on
  another volume, GC while the first is absent, and its return.
- [x] **M4-32 / P2 — Settle source cleanup obligations before drain retirement.**
  Migration deletes the source object before clearing its cleanup obligation
  (`crates/mb-node/src/volume.rs:914`). A crash at `MigrationSourceRemoved`
  leaves the obligation durable. Resume sees an empty source and retires it
  without clearing that record (`volume.rs:868`, `volume.rs:925`). Later GC
  waits permanently for the retired volume, whose store stays closed, even
  though its empty database is still attached (`volume.rs:603`). Reconcile
  outstanding obligations against the verified-empty source before declaring
  it removable. Extend transition coverage through retention/GC and reopen,
  asserting that receipts, cleanup obligations, and garbage candidates retire;
  the existing test only checks the retained payload and Retired state.
- [x] **M4-33 / P2 — Reserve accumulated WAL checkpoint growth.**
  `physical_write_reservation` budgets only the current row plus fixed overhead
  (`crates/mb-node/src/volume.rs:1299`), while SQLCipher checkpoints after
  1,000 WAL frames (`crates/mb-store/src/database.rs:2266`). Repeated inserts
  can accumulate several MiB of new pages in WAL before a threshold-crossing
  commit copies them into the main database. That write can pass admission
  with free space equal to headroom plus 400 KiB (`volume.rs:713`) and then
  consume MiBs of the reserve. The pinned SQLCipher source confirms that the
  automatic checkpoint copies all unbackfilled pages. Account for outstanding
  main-file growth or bound it with an appropriate checkpoint/reservation
  policy, including control writes on a shared filesystem. Cover many inserts
  across checkpoint thresholds at the headroom boundary; the one-object test
  at `volume.rs:2322` does not reach that boundary.

- [x] **Run the Milestone 4 correction gate after M4-28 through M4-33.**
  On 2026-09-15, the exact corrected source tree passed formatting, locked
  all-target workspace tests, and warning-free locked all-target workspace
  Clippy. A locally provisioned disposable 2 GiB Btrfs filesystem passed the
  complete `scripts/reflink-acceptance.sh` gate, including the strengthened
  shared-filesystem checkpoint/headroom boundary, generation-2 seed recovery,
  repeated multi-owner QUIC backup, five-daemon seed/DHT recovery after source
  and holder loss, and isolated direct/DCUtR/relay network paths. The new
  two-holder outage regression reconstructs after loss of each remaining host.
  Docker-controller safety checks also passed. All compilation and execution
  were local; no remote compilation server was used.

## Milestone 4 follow-up source review — prior correction record

Source review of `e663c49..8411f7d` found the remaining blockers below. The
2026-09-14 test results remain historical evidence for the cases they exercised;
they do not cover these combined failure schedules. This review ran no builds,
tests, or runtime probes. Close these findings and the correction gate before
advancing to Milestone 5.

- [x] **M4-15 / P1 — Preserve an uncommitted writer across unrelated checkpoints.**
  `writer_incarnation` accepts a pending incarnation only while its original
  `base_checkpoint` equals the current guild head, then permanently fences it
  otherwise (`crates/mb-node/src/node.rs:2154`). That base is never updated.
  If a first capture fails after the writer is persisted, another owner's
  backup advances the shared checkpoint without changing this owner's fence
  (`crates/mb-node/src/network/p2p.rs:6960`). Every later local backup fails,
  including after reopen, although no replacement writer was certified.
  Distinguish unrelated checkpoint progress from actual supersession. Cover
  interrupted first capture and recovery takeover, another owner's commit,
  retry/reopen, and continued rejection of a truly superseded writer.
- [x] **M4-16 / P1 — Migrate pending version-1 capture intents.**
  `CaptureIntent` inserts `captured_change_sequence` into its positional
  postcard encoding (`crates/mb-node/src/snapshot.rs:226`), while startup
  decodes only the new shape and requires version 2 (`snapshot.rs:243`). A
  pending capture written before `d1857b5` cannot be reconciled after upgrade;
  `Node::open_locked` propagates the error before starting service
  (`crates/mb-node/src/node.rs:595`). Add an explicit legacy decoder/migration
  that preserves owned capture cleanup and treats the unknown dirty generation
  conservatively. Cover upgrade with an interrupted version-1 capture.
- [x] **M4-17 / P1 — Isolate corrupt pending writes during startup.**
  A publication interrupted after READY commit leaves `volume-write-intent`
  durable (`crates/mb-node/src/volume.rs:671`). If that object's payload is
  corrupt, the database can still open, but `reconcile` propagates its
  `load_ready` integrity error (`volume.rs:690`). Startup requires this step
  to succeed (`crates/mb-node/src/node.rs:597`), so healthy storage and the
  scrub/repair controls become inaccessible. Quarantine/report the failed
  volume while retaining reconciliation evidence. Cover interruption after
  object commit, corruption, healthy replacement, and daemon reopen.
- [x] **M4-18 / P1 — Keep corrupt retired shards from blocking GC and startup.**
  `remove_unreachable` verifies payload bytes before deleting a certified
  unreachable object and propagates corruption even on a Failed volume
  (`crates/mb-node/src/volume.rs:537`). Retiring its group and advancing beyond
  the GC grace period makes checkpoint completion fail at
  `crates/mb-node/src/node.rs:3179`; every restart repeats GC at `node.rs:609`.
  Safely delete or defer the corrupt unreachable object using certified
  identity without making peer/control startup depend on valid obsolete
  payloads. Cover corruption, retirement, grace-period advance, and reopen.
- [x] **M4-19 / P1 — Reconcile relocated volumes by durable UUID before initialization.**
  A newly configured path enters `initialize_volume` before the existing UUID
  is checked (`crates/mb-node/src/volume.rs:339`). Its manifest branch resets
  Online/configured state and creates a missing database (`volume.rs:940`).
  Moving an absent established volume to a new path therefore bypasses database
  loss detection while retaining old receipts. Moving a Retired volume also
  silently reactivates it. Merge the discovered manifest with durable UUID
  state before any creation or activation. Cover a relocated established
  manifest with lost database and a relocated completed drain.
- [x] **M4-20 / P2 — Bound automatic-backup errors on UTF-8 character boundaries.**
  The new scan-error handler calls `message.truncate(512)`
  (`crates/mb-node/src/node.rs:908`). A failing descendant with a long Unicode
  path can place byte 512 inside a character and panic while holding the Node
  mutex. The task error propagates through `crates/mb-node/src/automation.rs:127`
  and terminates the daemon at `cmd/mutualbackup/src/bin/mutualbackupd.rs:151`.
  Apply character-safe bounds to scan and completion errors; test long Unicode
  failure paths with persisted blocked/retry status and continued service.
- [x] **M4-21 / P2 — Make emergency-copy classification recoverable after interruption.**
  `install_repaired_shard` commits the payload and volume receipt before
  separately writing its proof and emergency marker
  (`crates/mb-node/src/node.rs:2445`). A crash before the marker leaves an
  emergency information payload that healthy-group cleanup never enumerates
  (`node.rs:2484`) and retirement never schedules for volume GC (`node.rs:3065`).
  Volume reconciliation repairs receipts only. Persist/reconcile the repair
  classification across these commits. Cover interruption before proof/marker,
  reopen, restored assignments, retirement, and complete space reclamation.
- [x] **M4-22 / P2 — Keep GC work until every migration duplicate is collected.**
  Interruption after migration destination commit leaves both source and
  destination copies (`crates/mb-node/src/volume.rs:810`). GC deletes only
  the receipt-selected destination and returns success (`volume.rs:548`),
  after which its durable candidate is removed
  (`crates/mb-node/src/node.rs:3199`). The source survives; resuming its drain
  republishes already-collected data and a receipt with no cleanup candidate.
  Collect every duplicate or retain per-volume cleanup obligations, including
  unavailable sources. Cover migration interruption followed by retention/GC,
  reopen, source return, and resumed drain.
- [x] **M4-23 / P2 — Reuse repaired destinations when draining a returned volume.**
  Replacement repair stores the payload with an empty acknowledgement
  (`crates/mb-node/src/volume.rs:598`). If the original volume returns and is
  drained, migration retains the replacement receipt but republishes using the
  original nonempty acknowledgement (`volume.rs:788`, `volume.rs:805`). The
  database rejects the valid destination because those bytes differ
  (`crates/mb-store/src/database.rs:1503`). Reuse the verified destination while
  preserving repair/publication acknowledgement semantics. Cover source loss,
  replacement repair, original return, and completed drain at exact capacity.
- [x] **M4-24 / P2 — Report failed volumes even when their metadata is unreadable.**
  Scrub marks a database Failed on a read error but retains its store
  (`crates/mb-node/src/volume.rs:730`). Status still propagates errors from
  `used_bytes`, allocation, free-space, and object-count queries
  (`volume.rs:399`), so an unreadable table page or unavailable filesystem
  prevents reporting every volume. Return the failed entry with unavailable
  measurements and its error while preserving healthy entries. Cover metadata
  corruption after open, beyond the existing payload-only corruption fixture.
- [x] **M4-25 / P2 — Reserve physical database growth rather than payload length alone.**
  Placement compares only `object.bytes.len()` against free space minus
  headroom (`crates/mb-node/src/volume.rs:621`, `volume.rs:637`). A new 64 KiB
  object also requires row metadata, encrypted pages, and WAL space
  (`crates/mb-store/src/database.rs:1740`, `database.rs:2245`). With no reusable
  pages and free space equal to headroom plus 64 KiB, placement passes but
  consumes the reserve or fails during publication. Account conservatively for
  physical database/WAL growth. Cover the actual allocation boundary, including
  shared-filesystem control work, instead of only headroom exceeding all free
  space.
- [x] **M4-26 / P2 — Step incremental vacuum to completion before reporting reclaim.**
  Reclaim calls `PRAGMA incremental_vacuum` through `execute_batch`
  (`crates/mb-store/src/database.rs:1321`, `database.rs:1336`). The pinned
  rusqlite 0.37 implementation steps each statement once; bundled SQLCipher
  emits a result row after each vacuumed page. Each call therefore processes
  at most one page, leaving most of a deleted 64 KiB object's allocation behind.
  Consume the statement to completion and checkpoint afterward. Verify that
  reclaim drains the freelist and returns the expected allocation; the current
  test only checks for any decrease (`database.rs:3567`).
- [x] **M4-27 / P2 — Resume fresh-volume initialization after the empty database commit.**
  Initialization persists the manifest first
  (`crates/mb-node/src/volume.rs:986`), then commits an empty database via
  `VACUUM` before starting the application-schema transaction
  (`crates/mb-store/src/database.rs:1733`). A crash there leaves a manifest and
  nonempty database without tables. Retry skips creation because the file
  exists (`volume.rs:952`) and established opening rejects it (`database.rs:1228`),
  so the configured external volume prevents startup repeatedly. Persist
  authenticated initialization state distinct from established-data loss. Cover
  interruption before/after schema and registry commits and restart convergence.

- [x] **Run a new Milestone 4 correction gate after M4-15 through M4-27.**
  Commits `8162ffc`, `99d8ad5`, and `21486e4` close the combined failure and
  upgrade schedules. On 2026-09-15 the exact corrected tree passed locked
  workspace tests and warning-free workspace Clippy. A disposable local Btrfs
  filesystem passed the complete reflink/network gate, including the version-1
  capture migration, real shared-filesystem headroom boundary, generation-2
  seed recovery, repeated multi-owner QUIC backup, and five-daemon seed/DHT
  recovery after source and holder loss. Docker-controller safety and the real
  NAT-PMP lifecycle gate also passed. All compilation and execution were local;
  no remote compilation server was used.

## Milestone 4 initial review findings (prior correction record)

Source review of `7b1114a..b8ffc90` on 2026-09-14 reopened Milestone 4.
The findings below follow source paths and durable-state transitions; no builds,
tests, or runtime probes were performed for that review. The corrections in
`d1857b5` through `83ebf83` were marked complete and passed the recorded local
gate. The follow-up findings above identify remaining cases in that corrected
implementation; Milestone 4 was reopened until they were resolved.

- [x] **M4-01 / P1 — Allow seed recovery without historical checkpoints.**
  Recovery downloads the selected head, but `reconcile_garbage_collection`
  unconditionally loads its parent (`crates/mb-node/src/node.rs:2964`).
  `install_recovered_checkpoint` calls GC after durably installing that head
  (`node.rs:4060`), so blank-state recovery at generation 2 or later fails
  before file restoration; `Node::open_locked` repeats the failure on restart
  (`node.rs:593`). Make GC conservative when historical certificates are
  absent without weakening live-object protection. Verify seed-only recovery
  at generation >= 2, completed restoration, and close/reopen with only the
  selected certified head available locally.
- [x] **M4-02 / P1 — Keep a superseded writer fenced.**
  `writer_incarnation` silently replaces an existing superseded incarnation
  with `latest_epoch + 1` (`crates/mb-node/src/node.rs:2101`), while checkpoint
  reconciliation adopts the recovered head and marks the old machine's root
  dirty (`node.rs:2514`, `node.rs:2897`). Its next ordinary or automatic backup
  can therefore take ownership back and publish stale filesystem contents.
  Distinguish fresh recovery/explicit takeover from a fenced existing writer.
  Cover two independent data directories sharing a seed: after recovery
  establishes the replacement writer, backups and restarts on the old machine
  must remain fenced until an explicit takeover.
- [x] **M4-03 / P1 — Keep peer service online when automatic scanning fails.**
  `poll_automatic_backup` propagates root enumeration/metadata errors
  (`crates/mb-node/src/node.rs:888`, `node.rs:972`). The automatic worker
  propagates them (`crates/mb-node/src/automation.rs:15`), and the daemon's
  top-level select shuts down the node
  (`cmd/mutualbackup/src/bin/mutualbackupd.rs:151`). With automation enabled,
  a missing source directory or an entry disappearing during a scan can stop
  service instead of leaving a dirty, blocked root. Persist the reason and
  retry safely. Cover missing/unreadable roots and scan races while checking
  that peer/control service and later automatic reconciliation continue.
- [x] **M4-04 / P1 — Persist the captured dirty generation with the revision.**
  Capture commits the immutable revision and head first
  (`crates/mb-node/src/snapshot.rs:625`); `prepare_protected_backup` records
  `revision-root-change` afterward (`crates/mb-node/src/node.rs:1676`). A crash
  between these writes, followed by a source edit and retry, reuses the old
  snapshot but records the new dirty generation. Committing it then clears
  uncaptured changes (`node.rs:2833`); a missing generation also permits
  clearing. Bind the original generation to durable capture/retry state and
  treat missing evidence conservatively. Inject this interruption, edit the
  source, reopen/retry, and verify the root stays dirty until a new capture
  includes the edit.
- [x] **M4-05 / P1 — Use a verified emergency copy of the requested shard.**
  Audit reconstruction clears the target even when it already contains a
  verified emergency copy (`crates/mb-node/src/network/p2p.rs:6205`). With only
  indices {0,3,4} available and index 0 present only as an emergency copy, this
  leaves two inputs and aborts repair. Recovery/restore also excludes the
  target from emergency lookup (`p2p.rs:6586`), then requires three other
  indices. Consume verified target bytes directly. Cover audit, restore, and
  recovery with each emergency index as the target and exactly three surviving
  indices, including emergency information shards.
- [x] **M4-06 / P1 — Isolate corruption from healthy copies and status.**
  Scrub marks a corrupt volume Failed but retains its store
  (`crates/mb-node/src/volume.rs:649`). Local and pooled network readers stop
  on its first integrity error (`volume.rs:446`,
  `crates/mb-node/src/node.rs:507`), so it can mask a verified replacement on a
  later volume. Status also verifies every payload and fails on the corruption
  (`volume.rs:380`). Preserve integrity errors while trying healthy copies,
  and keep failure/status reporting available. Cover corruption, scrub,
  replacement repair, local/network reads, and restart with either ordering
  of source/replacement UUIDs.
- [x] **M4-07 / P1 — Retire network readers before declaring a disk removable.**
  P2P snapshots the volume reader configuration at startup
  (`crates/mb-node/src/network/p2p.rs:1209`); checkout reuses pooled handles or
  that fixed configuration (`crates/mb-node/src/network.rs:197`). Migration
  drops only the writer handle before reporting "safe to remove volume"
  (`crates/mb-node/src/volume.rs:753`). Pooled readers retain the old filesystem;
  fresh readers still open every old path before serving even control reads
  (`crates/mb-node/src/node.rs:408`). After detach this can fail unrelated peer
  reads or recreate an empty database at a writable exposed path. Refresh
  membership, evict retired handles, and use noncreating reader opens. Cover
  live drain, physical detach, and continued profile/checkpoint/parity reads
  without restarting the daemon.
- [x] **M4-08 / P1 — Detect loss of an established parity database.**
  `open_volume_store` verifies the manifest but opens a missing database with
  creation enabled (`crates/mb-node/src/volume.rs:921`,
  `crates/mb-store/src/database.rs:2113`). A database truncated to zero bytes is
  also initialized under the old UUID (`database.rs:1614`). Existing receipts
  survive, while the volume can appear Online with zero objects. Distinguish
  first initialization from reopening acknowledged storage and record loss
  instead of silently recreating it. Test removal and truncation of only an
  established database while retaining its manifest and control receipts;
  require explicit replacement/reconciliation and visible degradation.
- [x] **M4-09 / P2 — Migrate repaired and emergency objects.**
  `store_repair` stores valid objects with an empty acknowledgement
  (`crates/mb-node/src/volume.rs:536`), but migration always calls
  `load_acknowledgement` (`volume.rs:720`), which rejects empty values
  (`crates/mb-store/src/database.rs:1484`). Any such object blocks completion
  of a drain. Preserve the distinct acknowledgement semantics of ordinary
  publication and repair, and cover migration of assigned repairs plus
  emergency information and parity objects.
- [x] **M4-10 / P2 — Resume migration without reserving duplicate capacity.**
  An interruption after destination commit leaves both copies and a receipt
  naming the destination. Retry deletes that receipt
  (`crates/mb-node/src/volume.rs:729`) and demands space for another whole
  object (`volume.rs:574`) before discovering the already verified copy.
  Reuse committed destination state. Cover interruption after destination
  commit with a destination budget exactly equal to the copied payload,
  followed by reopen/reconcile and successful drain; the existing interruption
  fixture allows twice that capacity (`volume.rs:1473`).
- [x] **M4-11 / P2 — Preserve completed drains through daemon configuration.**
  Migration persists Offline/configured=false (`crates/mb-node/src/volume.rs:753`),
  but daemon startup reapplies the TOML volume paths
  (`cmd/mutualbackup/src/bin/mutualbackupd.rs:563`) and `configure` makes the
  drained volume Online again (`volume.rs:313`). A disk declared removable can
  accept new writes after restart. Preserve retirement until explicit
  reactivation. Test the actual open-and-configure startup sequence with
  unchanged configuration, not only `StorageVolumes::open`.
- [x] **M4-12 / P2 — Complete emergency-copy cleanup across checkpoint changes.**
  Cleanup requires the copy's creation checkpoint to equal the latest hash
  (`crates/mb-node/src/node.rs:2441`), so advancing the checkpoint while keeping
  the group prevents cleanup after assigned protection returns. Separately,
  retiring an information role schedules only `gc-sector` (`node.rs:3003`),
  which deletes a control recipe rather than its emergency volume payload
  (`node.rs:3095`). Such retired copies retain their bytes, receipts, proofs,
  and markers indefinitely. Validate cleanup against the current certified
  group/root and collect emergency copies of every role after the certified
  grace period. Cover checkpoint advance, assigned repair, group retirement,
  restart, and capacity reclamation for information and parity copies.
- [x] **M4-13 / P1 — Bound memory for storage status and migration.**
  `ready_objects` collects all full shard payloads into one vector
  (`crates/mb-store/src/database.rs:1241`). Both status and migration use it
  (`crates/mb-node/src/volume.rs:386`, `volume.rs:713`), so a routine status
  request can exhaust daemon memory when stored parity exceeds RAM. Count
  metadata without loading payloads and migrate verified objects in bounded
  batches. Verify memory bounds independently of total stored volume size.
- [x] **M4-14 / P2 — Implement physical-space accounting and reclamation.**
  The volume requirements in `plan.md` distinguish logical quota from physical
  allocation and require reclaim plus operational headroom. Current accounting
  only sums payload lengths (`crates/mb-store/src/database.rs:1231`), placement
  subtracts logical headroom (`crates/mb-node/src/volume.rs:567`), and collection
  only deletes rows (`database.rs:1348`). There is no implemented physical-space
  accounting or database reclaim operation. Track allocated database/WAL space
  and available filesystem space, preserve recovery/GC headroom, and provide
  controlled reclaim. Cover deletion/reclaim and a nearly full filesystem
  independently of the configured logical quota.

- [x] **Re-run the Milestone 4 closure gate after corrections.** On 2026-09-14,
  the exact corrected source tree passed locked workspace tests and warning-free
  workspace Clippy. A locally provisioned disposable Btrfs filesystem passed
  `scripts/reflink-acceptance.sh`, including capture interruptions,
  generation-2 seed recovery over QUIC, close/reopen and GC, and real
  five-daemon recovery from seed and DHT after source loss. Focused regressions
  cover corruption and healthy-copy fallback, live detach/replacement, repair
  followed by another loss, retention/GC, absent-source operation, partial
  peer availability, physical headroom/reclaim, retired-volume configuration
  replay, and nonempty SQLCipher rekey for both control and parity databases.
  Docker-controller safety and real NAT-PMP lifecycle gates also passed during
  the correction series. All compilation and execution were local; no remote
  compilation server was used.

## Milestone 5 guild geometry and coding protocol (closed 2026-09-30)

The historical source-only review of the Milestone 5 changes through `a6b5d7d`
found three blockers: negative verifier evidence could terminate retry
ownership and block replanning (M5-119); an expiring format-2 launch could
renew beside a live format-3 retry for the same lane (M5-120); and stale
cleanup could forget an offline removed holder's staged data (M5-121). The
review required these corrections and a new exact-source M5-122 local gate.
All three corrections and M5-122 passed on exact source `4880c28`. A later
source-only review of the corrections through `8712ac3` found four blockers
(M5-123 through M5-126). Those findings were corrected in `9cfa4b5`,
`dd942a6`, and `e09a13f`; the complete M5-127 local gate passed on exact code
source `e09a13f`. A later source-only review of that same code found M5-128
through M5-130 and reopened Milestone 5. M5-127 remains passing evidence for
its exercised cases, but it did not cover those schedules. The corrections and
regressions were committed through `39a99e7`, and the complete local M5-131
gate passed on that exact source. A source-only review of the unchanged code
found M5-132 and M5-133 below. Their corrections passed the complete local
M5-134 gate on exact code source `a7da0ce`. A source-only review of that code
found M5-135 and M5-136 below, so Milestone 5 is reopened and Milestone 6
waits. M5-134 remains passing evidence for its exercised cases; this review
ran no builds, tests, daemons or runtime probes. M5-131 remains passing
historical evidence for its exercised cases.
M5-122 and M5-114 remain historical evidence for their exact source trees.

M5-116/M5-117 implementation update (2026-09-26): acknowledged retry parents
now remain quiescent only while their successor is live and unfenced, or after
explicit terminal cleanup/submission ownership. Expired, stale or retired
successors without accepted evidence are reclaimed durably. A fence never
proves holder deletion, regardless of descriptor presence or a delayed
delegation acknowledgement. Retry execution reports successful cleanup
separately from acknowledgement. Only confirmed cleanup or authenticated
submission ownership can release input intent and publish terminal metadata.
Accepted child result/failure
owners win successor retirement arbitration under the writer lock; late parent
completion preserves child-owned input intent. Terminal metadata binds the
exact signed child without changing persisted job encodings or signed records.
The first complete workspace run exposed M5-118: expired-launch renewal did
not coalesce with a recovered live retry successor. M5-118 is corrected, and
the final M5-114 workspace and fresh provisioned gate passed on exact source
`720920def00323c7efbcc347df8447e3e98fa6ec`. Milestone 5 was closed at
that gate; the later source-only review above reopens it. All compilation and
execution for the historical gate were local.

Earlier source-review record:

Latest source-only review covers `88898a6..687e207` and the pending M5-116
changes in `crates/mb-node/src/node.rs` and `network/p2p.rs`. The committed
M5-111/M5-112/M5-113/M5-115 corrections preserve cleanup/submission ownership
and restage packed retry inputs. The pending M5-116 correction makes
acknowledged successor expiry and stale cleanup reachable, but introduces
M5-117: a retirement fence and absent input descriptors can be mistaken for
completed holder cleanup. M5-116 remains uncommitted; resolve M5-117 before
the complete final M5-114 gate. Milestone 5 is unfinished and Milestone 6
waits. This review ran no builds, tests, daemons, or runtime probes and changes
only these status documents. Existing passing results remain historical
evidence for their recorded source.

Earlier review record:

Source-only review of `16c28a5..88898a6` on 2026-09-26 finds three outstanding
P1 blockers in the production cleanup/retry paths: stale membership cleanup
can discard concurrently accepted verifier evidence (M5-111); a signed failure
arriving during expired-launch recovery can terminate the daemon (M5-112);
and failed packed-input attempts retry without restaging their deleted inputs
(M5-113). Correct these and complete the new M5-114 local gate before closure.
Milestones 0 through 4 remain passed; Milestone 6 waits. This review ran no
builds, tests, daemons, runtime probes, or remote compilation. The earlier
M5-104 passing results below remain historical evidence for their exact source;
their regressions do not cover these report/cleanup interleavings or packed
inputs available only through the original attempt's placement.

Previous closure record:

M5-103 and M5-105 through M5-110 are implemented. The complete final M5-104
gate passed locally on exact source `f8e47d34d62a073db6953260571441525dc5e2ac`:
locked all-target workspace tests, strict locked all-target Clippy, formatting,
Docker lab safety, and all 23 fresh disposable Btrfs/network acceptance
invocations. The acknowledged-launch, accepted-result, ownership, fairness,
staging and membership-transition regressions pass in the full workspace run.
Owner/storage-only seed recovery and direct, DCUtR and forced-relay bulk
transfers pass in the final daemon scenario. Disposable filesystem, loop device,
namespaces, network rules/interfaces and test processes were independently
confirmed removed. All compilation and execution were local. Milestone 5 was
closed at that point. Exact outcomes are recorded under M5-104 below.

The following paragraphs retain earlier review and correction history.

The final corrected source `c7033fa` passed the complete M5-97 local gate on
2026-09-26. Provisioned acceptance ran at `4170dce`, which changes only these
status documents from that source. M5-92 through M5-102's recorded corrections
remain implemented, but source-only review through `515260c` found M5-103:
a preserved incomplete retry can indefinitely prevent the background worker
from dispatching a stronger replacement or finishing unrelated activations.
M5-103 is now implemented with passing production-worker restart regressions.
Source-only review through `c4e97f8` finds M5-105 and M5-106 in retry lane
coalescing and its production staging caller. Both corrections are now
implemented with passing restart/replanning regressions. Milestone 5 remains
open; the M5-107 membership-transition follow-up also passes its focused
checks. Source-only review of `c4e97f8..1f3141e` found M5-108 and M5-109:
expired durable launches cannot renew, and blocked staging launches hide
later runnable launches. Both corrections and all 21 focused tests now pass;
the complete new M5-104 gate remains required. Source-only review of
`1f3141e..16c28a5` finds M5-110: successfully dispatched current-epoch
launches are skipped even after expiry, leaving coordinator-loss recovery
unreachable. M5-110 is now implemented with passing coordinator-loss,
accepted-result, and lineage regressions. The complete final M5-104 gate remains
required. Milestone 6 waits.
M5-97 and earlier gate records remain evidence for their exact trees. This
review ran no builds, tests, daemons, runtime probes, or remote compilation.

Source-only review of `8135e0b..da8974a` on 2026-09-18 found the M5-36 through
M5-44 blockers below; all are now corrected. The production gate recorded in
M5-35 remains valid evidence for those scenarios, but predates the corrected
tree. The complete M5-45 correction gate passed locally on 2026-09-19, so
it remains historical evidence for that tree. Follow-up source-only review of
`56bb57d..f7d0503` on 2026-09-20 found M5-46 through M5-57 below. Their
corrections are recorded under those items, but a fresh source-only review of
`f7d0503..81ec33b` on 2026-09-21 found M5-58 through M5-66. Those source
blockers are now corrected, and the follow-up source-only review finds no
remaining Milestone 5 blocker. The final M5-67 local workspace/provisioned gate
passed on 2026-09-22 and remains historical evidence for that exact tree. A
fresh source-only review of `81ec33b..b65c79a` on 2026-09-22 found M5-68 through
M5-76 below and reopened Milestone 5. Those source blockers are corrected. A
follow-up source-only review found no remaining implementation blocker. The
complete M5-77 local workspace/provisioned closure gate passed on 2026-09-22,
but source-only review of `b95811b..168945a` on 2026-09-25 found the remaining
M5-78 through M5-83 blockers below and reopened Milestone 5. M5-77 remains
historical gate evidence for its exact tree; Milestone 6 waits for corrections
and a new closure gate. The fresh review ran no builds, tests, daemons, runtime
probes, or remote compilation.

Source-only follow-up review on 2026-09-25 covered `b9d4e07..8434b30` and the
two then-local node-source edits. It found a repeated-roster legacy authority
rollback and missing scenario gates; that review ran no builds, tests, daemons,
runtime probes, or remote compilation. Subsequent local correction commits
through `484e4ec` address that rollback, exercise mixed legacy evidence and
persistent checkpoint-head fallback, index committed generations, stream the
attestation journal, prefer replacement shards, and release failed relay
circuits immediately. Source-only review of `ae9e6c3..484e4ec` on 2026-09-25
found M5-82's stalled-STOP gate covered. Subsequent commits `40d83ec`,
`7287a4a`, `f58d64e`, `df014c1`, and `e959d92` cover the M5-79 through M5-81
scenario and resource gates below. That source-only review ran no builds, tests,
daemons, runtime probes, or remote compilation. Fresh source review of the final
correction commits found no new blocker. M5-84 passed locally on 2026-09-25 on
`e959d92`; that closure record remains evidence for its exact tree. At that
point, no code commits had followed `890d88c`, but a new source-only review of
the correction series found M5-85 through M5-87 below, reopening Milestone 5
at that time.
Subsequent commits `e9fadb2` and `75d0fd5` correct M5-85 and M5-86;
source review of `1e8ee2b` found M5-87 still could not prove a live `k` in a
multi-live-sector replacement group. Commit `dd5c7e8` corrects that path and
adds positive and negative multi-live-sector coverage. The complete local
M5-88 closure gate passed on 2026-09-25 for its source tree. A further
source-only review found M5-89 and M5-90 below, reopening Milestone 5; Milestone
6 waits. These source-only reviews ran no builds, tests, daemons, runtime
probes, or remote compilation.
Commits `e63d538` and `09e9379` correct M5-89 and M5-90, and the complete
M5-91 local gate passed on the latter source tree. A further source-only review
of `6bc66bd..543fb9b` found M5-92 through M5-96 below. M5-91 remains
historical evidence for source commit `09e9379`; Milestone 5 is reopened and
Milestone 6 waits for corrections and M5-97. This review ran no builds, tests,
daemons, runtime probes, or remote compilation.
Commits `1998700`, `ce3a96e`, `5b2b1a8`, and `308b156` address the restore,
live-quorum, mixed-coverage, cold-root, and retained-revision/audit paths.
Source-only review of `308b156` found the remaining checkpoint-signing gap
under M5-92 and M5-96: matching two independently signed root claims does not
prove they describe the same bytes. M5-97 also remains open. This review ran
no builds, tests, daemons, runtime probes, or remote compilation.
Commit `c7cc6fd` adds a version-three legacy coding plan whose signed manifest
carries complete encrypted information bytes. Transcript replay recomputes the
group's Merkle commitment and plan flat root from those same bytes. New legacy
checkpoint coverage requires that proof; format-1/2 transcripts remain valid
for historical checkpoints but cannot protect a new one. Focused local tests
pass for forged claims, retained revisions, and a correct old revision without
a signed Merkle commitment. M5-92 and M5-96 are corrected; M5-97 remains open.
Source-only review of `c7cc6fd..e64f76e` on 2026-09-26 finds M5-98 through
M5-100 below: the stronger legacy proof cannot reliably replace durable old
attempt/group evidence, and its raw-byte bound does not ensure it fits the
CBOR peer transport. Milestone 5 remains open; Milestone 6 waits for these
corrections and M5-97. This review ran no builds, tests, daemons, or runtime
probes and used no remote compilation.
The follow-up corrects M5-98 through M5-100 with distinct durable identities,
authenticated READY input reuse, compact full-byte manifests, and encoded
peer-frame budgets. Focused local migration, checkpoint, lifecycle, and
transport regressions pass. M5-97 remains the final closure gate.

The first closure record at `8135e0b` was premature. A follow-up source audit
found the remaining production gaps below. Commit `eeffd45` makes removal or
relabel exclude old placement from new coverage, invalidates stale audit state,
queues replacement coding without duplicating durable retries, and preserves
old layout readability. Its complete node library suite and warning-free core/
node Clippy gate passed locally. No remote compilation server was used.

- [x] **M5-01 / P1 — Protect multiple named roots with independent revision chains.**
  Signed revision format 3 and checkpoint format 6 or later bind every revision and
  retention tombstone to a protected-root UUID. The node keeps durable heads,
  dirty state, watcher signals, automatic scheduling, status, explicit backup
  selection, snapshot selection, and retention per root. Recovery atomically
  installs all certified root heads, registers the restored root under its
  signed ID, and continues that chain after restart. Focused model, retention,
  recovery-store, local-control, and restart regressions pass; the ignored
  provisioned Btrfs/QUIC gate now covers two roots for one owner and exact-root
  restore.
- [x] **M5-02 / P1 — Integrate stable-slot incremental packing into production.**
  Checkpoint format 7 authenticates the incremental `PackedCatalog`, including
  each packed sector's flat root and Merkle commitment. Backup packs all
  retained signed sectors into stable 16 KiB slots, persists the resulting
  64 KiB sectors, and codes their catalog IDs through the variable protocol.
  Coverage, lifecycle replacement, delayed GC, seed recovery, normal repair,
  and restore all resolve signed revision sectors through that catalog.
  Repacking can reuse a prior locally stored or reconstructed packed copy when
  an original owner is offline. Core partial-unpack and layout regressions plus
  node persistence/reopen coverage pass; the production Btrfs/QUIC gate checks
  stable slot positions across updates from two owners and two roots.
- [x] **M5-03 / P2 — Rank a delegated coder by every bulk lane path.**
  Peer protocol 2 adds fresh, signed, request-bound path observations over a
  canonical list of at most 256 active guild members. Each candidate reports
  its live or selected direct, relay, or Tor path to every real information
  source and parity destination. Initial attempts and retries rank the sum of
  those bulk edges, omit the candidate's own transfer when it participates,
  prefer a participant when totals tie, and retain relay/Tor as higher-cost
  available paths. The separate verifier still uses ordinary reachability and
  does not need a complete bulk-path report. Schema, snapshot, ranking, node
  library, and warning-free all-target node Clippy checks pass locally.
- [x] **M5-04 / P1 — Authorize delegated coders to fetch their signed inputs.**
  The first corrected production-gate run found that an ephemeral coding
  coordinator could stage parity but `GetCodingInformationRange` still fell
  through to the static guild-coordinator check. The first cross-user backup
  therefore accumulated retries whenever ranking selected another member.
  Treat the plan-scoped range request like the other delegated coder operations:
  only the signed plan's coding coordinator may issue it, and that caller must
  still be an active guild member.
- [x] **M5-05 / P1 — Preserve room for incremental cross-user packing.**
  The next production-gate run completed all four checkpoints but found that
  the first owner had filled every slot in its sectors. Stable positions then
  forced a later owner into separate sectors, so the authenticated catalog was
  multi-owner without any cross-user sector. New allocation keeps one vacancy
  in a single-owner sector, fills vacancies from other owners before extending
  a same-owner sector, and packs mixed sectors densely. A regression adds a
  later owner without moving any prior source chunk and requires a mixed sector.
- [x] **M5-06 / P1 — Exercise recovery-key registration in the production path.**
  The next gate passed the corrected catalog invariant and both local restores,
  then found that its manually assembled runtime had started delegated coding
  but omitted the daemon's peer-exchange worker. Format-7 DHT publication
  correctly waits for a current recovery-key epoch for every active subject, so
  all six publication passes returned without publishing. Run the real
  peer-exchange worker for every test node and wait for the certified recovery
  epochs before starting production backups.
- [x] **M5-07 / P1 — Fence coding-group lifecycle during checkpoint construction.**
  Running the production peer-exchange worker exposed that lifecycle
  reconciliation compared newly activated groups only with the still-current
  checkpoint. It retired every group created for the running backup draft, so
  that draft could never reach coverage. Treat a durable `Running` backup job
  as a checkpoint-construction fence: recovery-key and endpoint exchange still
  proceed, while group retirement waits until the job commits or is deferred.
  The production test now claims each backup job before constructing it, as the
  daemon coordinator does.
- [x] **M5-08 / P1 — Exercise the daemon's renewable DHT publication loop.**
  The next production run completed all four checkpoints, verified the packed
  catalog and local restores, then found zero recovery-readiness publishers on
  every node. Each node had built four current bundles, but the test cold-started
  provider announcements only after the 43-minute workload and allowed roughly
  three seconds for Kademlia convergence. Run the daemon's real five-second DHT
  publication/readiness worker on every node throughout the production test,
  then wait under a 60-second deadline for all subjects to certify three current
  publishers for the final checkpoint.
- [x] **M5-09 / P1 — Accept current recovery-key bundles for later dynamic checkpoints.**
  With real DHT workers running throughout checkpoints 1 and 2, every readiness
  pass still retained zero publishers. Replaying each publisher's exact stored
  bundle through the production validator found that publication correctly made
  format-2 epoch envelopes for checkpoint 7, but validation admitted them only
  for checkpoint 4. Apply the dynamic recovery-key rule to every currently
  supported dynamic checkpoint format, 4 through 7, and regress that range.
- [x] **M5-10 / P1 — Accept current recovery-key epochs during cold recovery.**
  The corrected production run completed all four checkpoints, current DHT
  readiness, packed-catalog checks, and local restores, then timed out starting
  large recovery with three live holders. Bundle admission accepted checkpoint
  formats 4 through 7, but recovery-head certification independently admitted
  current-epoch bundles only for format 4. Apply the same dynamic checkpoint
  range during certification and regress every supported version.
- [x] **M5-11 / P1 — Establish watcher coverage before backup capture.**
  The next production run again completed all coding transcripts, then found
  node 2 dirty before the deliberate post-restore source edit. Its durable
  record showed that capture saved dirty generation 1 while the asynchronously
  started watcher later wrote generation 2 for startup reconciliation. Install
  every filesystem watch before advancing that generation, expose a readiness
  signal, and require the production path to observe it before capture.
- [x] **M5-12 / P1 — Pin cold recovery against its certified dynamic state.**
  The next production run completed all 51 coding transcripts and entered cold
  recovery, then rejected a current-epoch recovery bundle because recovery
  attempt pinning ran before dynamic guild adoption and re-read the necessarily
  absent local dynamic state. Pass the already certified downloaded state into
  recovery-observation reconciliation while retaining local-state validation
  for ordinary readiness, and regress pinning on a fresh node with no installed
  dynamic state.
- [x] **M5-13 / P1 — Fetch cold-recovery coding evidence concurrently.**
  The corrected run passed M5-12, installed the recovered dynamic guild and all
  51 coding transcripts, then exhausted the 60-second recovery bound before
  staging its first assigned shard. Recovery-head validation fetched every
  transcript serially from each candidate, consuming the window before shard
  reconstruction began. Fetch transcript evidence with bounded concurrency,
  leaving the existing outbound semaphore as the global network limit, and
  regress that the collector is concurrent without exceeding its bound.
- [x] **M5-14 / P1 — Fetch coding evidence from one certified publisher at a time.**
  The next run again completed all four checkpoints and 51 transcripts, but the
  fresh node timed out before adopting guild state. Recovery-head validation
  started an eight-request transcript fetch for every candidate concurrently,
  exactly filling the test's global eight-request limit. Requests to the two
  stopped publishers could therefore hold every permit for a full protocol
  timeout while live publishers redundantly fetched the same 51 transcripts.
  Validate candidate genesis, checkpoint, and event history first, then fetch
  transcript evidence only from a publisher whose state has enough independent
  current locators. If that publisher cannot serve the evidence, continue with
  another certified candidate rather than starting duplicate bulk fetches.
- [x] **M5-15 / P1 — Stop retrying known-missing holders during variable recovery.**
  The next run completed all four checkpoints, certified one recovery head,
  installed the full event history and 50 retained transcripts, then timed out
  after activating only two of 21 locally assigned variable shards. The
  variable recovery scheduler always issued `needed + 1` requests. It let the
  fresh node's known-missing local assignment occupy the initial spare, then
  continued including a known-offline holder even after exactly `k` healthy
  remote holders had been learned. Each abandoned request retained a global
  outbound permit until its terminal event. Mark the absent local assignment
  deferred before fetching, use all remote candidates for the first probe, and
  once `k` preferred holders remain issue only those `k`, matching the bounded
  legacy recovery schedule. A focused regression pins both selections.
- [x] **M5-16 / P1 — Reconstruct independent variable groups concurrently.**
  The next run again completed the production workload and installed all 51
  recovered transcripts, but still timed out after activating two of 21 local
  variable shards. Holder selection no longer repeated known-dead requests;
  the remaining work was serialized across otherwise independent groups. Probe
  one group first so its results seed the shared deferred-holder set, then
  reconstruct and activate the remaining groups with bounded two-group
  concurrency. Each group still uses the existing bounded candidate set and
  every request remains subject to the global outbound semaphore.
- [x] **M5-17 / P1 — Keep the variable-recovery pipeline full.**
  The first run with concurrent variable recovery completed all four production
  checkpoints, installed all 59 guild events and all 51 transcripts on the
  fresh node, and proved that known-dead holders no longer consumed the global
  request budget. It still timed out after activating only five of 21 local
  shards. Limiting the whole recovery to two groups serialized too much local
  Reed-Solomon, commitment, and durable activation work after each bounded
  shard fetch. Allow eight independent group workflows in flight; their shard
  traffic remains constrained by the P2P client's existing global outbound
  semaphore, so this fills the local pipeline without weakening the transport
  request bound.
- [x] **M5-18 / P1 — Verify recovered coding evidence once.**
  A durable-state resume probe showed that group concurrency was no longer the
  dominant cost: even with every assigned shard already present, recovery spent
  about 50 seconds replaying the same 21 coding transcripts and their 59-event
  authority history during planning and activation. Each remote transcript is
  now fully replayed once on a bounded blocking worker before a typed verified
  value crosses the recovery trust boundary. Adoption stores that evidence in
  both durable indexes atomically with certified guild state; later staging and
  activation require an active checkpoint pin, an exact retained group, and
  byte-identical records in both indexes instead of repeating the proof and
  event-history replay. Reed-Solomon reconstruction also runs off the async
  reactor, and a live assigned target shard is fetched directly before falling
  back to any-`k` reconstruction. The same durable resume path fell from 53.27
  seconds to 11.91 seconds while retaining full evidence validation at ingress.
- [x] **M5-19 / P1 — Resume an installed recovery without replaying guild history.**
  The fresh gate completed cold recovery within its 60-second bound, installed
  all 59 guild events and 51 transcripts, and restored the selected root. After
  the original peers stopped, however, its required one-second offline resume
  timed out because `resume_local_recovery` replayed the complete certified
  event history through ordinary membership validation. The local resume path
  now treats the atomically installed recovery state as its trust boundary. It
  still validates checkpoint structure; binds the installed guild and genesis,
  local Node ID and recovery key, legacy local signature, and current active
  member; and lets the completed recovery job revalidate its target identity.
  A diagnostic against the preserved production state fell to 325 ms without
  any live peer or DHT path.
- [x] **M5-20 / P1 — Do not block certified-state adoption on endpoint refresh.**
  The fresh gate reached a pinned recovery attempt but again exceeded 60
  seconds before adopting guild state. Its durable database contained the four
  validated recovery observations and the active attempt, but no installed
  checkpoint, event, or transcript record. Source review found four optional
  DHT endpoint-record lookups between those transitions. Every accepted
  recovery locator already contains a signed, unexpired endpoint set, and the
  validator requires enough independent current locators before pinning.
  Recovery now installs those locator endpoints directly and adopts certified
  state without waiting for another DHT round. Normal peer exchange can refresh
  endpoints after adoption.
- [x] **M5-21 / P1 — Drain inbound workers before releasing the node runtime.**
  The next clean gate passed bounded cold recovery, post-recovery publication,
  and the one-second offline local resume, then failed when reopening the
  recovered data directory after P2P shutdown. Inbound request handlers were
  detached blocking tasks, so the event loop could return while a completed
  handler still retained `Arc<Node>` and its process-lifetime directory lock.
  The event loop now tracks and reaps completed workers during normal service,
  closes their result receiver at shutdown, and joins every remaining worker
  before returning. A focused regression pauses a worker after its response is
  visible, proves shutdown remains pending, releases it, and reopens the same
  data directory successfully.
- [x] **M5-22 / P1 — Do not let one peer stall guild-event synchronization.**
  The next clean run stopped at initial recovery-key readiness. Every one of the
  five nodes had converged on exactly event sequence 2 with two current recovery
  keys, then made no progress for the rest of the 60-second bound. Guild-event
  synchronization issued requests to every peer and awaited all of them before
  accepting any tail, while one logical request may retry for 90 seconds. That
  put the reconciliation step behind a single delayed peer even though each
  accepted event tail is independently quorum-certified and replay-validated.
  Synchronization now advances on the first valid certified tail and retries
  other peers on the next periodic pass. Coding-group evidence is fetched from
  the selected event source before that event is installed.
- [x] **M5-23 / P2 — Keep process acceptance aligned with dynamic guild status.**
  The corrected multi-owner QUIC production scenario passed from a fresh
  Btrfs image in 2,521 seconds, including cold recovery, offline resume, and
  shutdown/reopen. The following five-daemon CLI test then stopped immediately
  after a successful finalize because two process tests still expected the old
  fixed-size `members: 5 of 5` display. Milestone 5 intentionally removed that
  hard-coded denominator when guild membership became dynamic; the live and
  reopened coordinator both reported an active epoch-1 guild containing all
  five authenticated members. Both direct and onion process tests now assert
  the current exact `members: 5` status line.
- [x] **M5-24 / P1 — Serialize initial recovery registration before coding.**
  After the status assertion was corrected, the direct five-daemon process
  test timed out on its first backup. All nodes had converged on event sequence
  1, but recovery-key registration and coding activation concurrently proposed
  different events at sequence 2. Their unanimous votes split two-to-three, so
  neither event could commit; subsequent recovery retries also generated fresh
  randomized envelope bytes and correctly hit the durable anti-equivocation
  locks. Coordinator backup claims now remain pending until every active member
  has a current recovery-key epoch. A subject whose registration attempt lacks
  quorum reloads and resubmits its exact durably signed event. Focused tests
  prove both the admission fence and exact signature-lock recovery.
- [x] **M5-25 / P2 — Bound process backup waits for delegated coding work.**
  With initial event ordering fixed, the direct process test committed its first
  backup and timed out while its second remained healthy and continued
  producing coding transcripts. The preserved 190 KiB job resumed immediately
  and committed after another 212 seconds, for more than 332 seconds of useful
  work across the interruption. The old 120-second bound predated sampled
  delegated coding. Process acceptance now allows ten minutes for its 180–190
  KiB backups and thirty minutes for its interrupted 1 MiB backup, while still
  treating failed durable jobs as immediate failures.
- [x] **M5-26 / P1 — Converge interrupted coding and lifecycle events.**
  The large interrupted process backup remained `Running` through its initial
  thirty-minute bound. Durable inspection showed no useful progress at event
  sequence 22: a retirement proposal signed between backups held sequence 23,
  the running backup fence prevented lifecycle replay, activation selected
  other groups ahead of the locked event, and restart planning reissued an
  initial deterministic attempt whose completed retry was already durable.
  Backup claims now wait behind an unrelated locally signed next event;
  lifecycle may finish its exact locked retire/forget event across a running
  job; activation selects the transcript named by a locked group event; and
  durable retry or verifier evidence suppresses resurrection of the original
  launch. The
  preserved deadlocked run advanced from sequence 22 through 42 and committed
  in 1,138 seconds with no recurring conflict. The large process bound is sixty
  minutes to cover its measured coding and serial event-activation workload.
- [x] **M5-27 / P1 — Let a backup resume its own writer-key event.**
  The next fresh five-daemon run stopped before coding: its first backup had
  durably signed a writer-key rotation, collected four of five signatures, and
  deferred, but M5-26's initial blanket signature-lock fence then prevented the
  same pending job from reclaiming itself. Backup claiming now admits only a
  locked `RotateWriterKey` whose owner matches the job and continues to defer
  behind every unrelated event. The regression covers both cases. Reopening
  that preserved run with the corrected binary advanced immediately and
  committed checkpoint `882eca8d785f5952bae322a50b16a331e4a278b51f87dc9445ee4f813c678ad1`
  in about two minutes.
- [x] **M5-28 / P1 — Bound the isolated-topology coding workload realistically.**
  After the backup/restart path passed, the fresh process run reached its
  512,031-byte topology backup over direct, hole-punched, and relay paths but
  hit that step's legacy 180-second CLI timeout. Its durable state contained 51
  activation jobs, 41 completed transcripts, and 27 launch jobs, with only the
  topology revision still running. Resuming those exact databases locally
  advanced the guild from event sequence 52 through 80 and committed checkpoint
  `3a1abf9e4163b2ca4a81f971f9737687a9c4a3fb0f9ddb9cbd340b7e15a35f24`
  after about fifty more minutes, over fifty-three minutes of useful work in
  total. The constrained-topology backup now has a separate ninety-minute
  bound; durable failed jobs still terminate immediately.
- [x] **M5-29 / P1 — Keep a waited backup attached across transient transport loss.**
  The next fresh gate passed the repeated multi-owner production scenario in
  2,699 seconds and reached the final isolated-topology backup. The coordinator
  durably contained that fourth backup job, but the owner's `backup --wait`
  command terminated when a submission acknowledgement or later status poll
  exhausted every transport tier during concurrent relay/coding traffic.
  Classify delivery deadlines, transport-attempt exhaustion, terminal outbound
  failures, and explicit retryable peer responses as retryable P2P failures.
  A waited backup now resubmits its deterministic descriptor and repeats status
  polling across those failures; idempotent coordinator admission preserves the
  one durable job. Non-waiting calls and permanent peer/protocol failures still
  return immediately. Focused regressions cover retry and classification.
- [x] **M5-30 / P2 — Bound cold recovery by its complete measured work.**
  The next fresh gate completed all four production backups but stopped after
  3,068 seconds when three-holder cold recovery exceeded its 60-second test
  allowance. The preserved recovery node had pinned generation 4, adopted the
  same event sequence 60 and 50 active groups as every live peer, and stored all
  50 required transcripts in both durable indexes; it had not yet staged a
  shard or committed the checkpoint. Replaying that exact variable-shard phase
  over fresh local QUIC sessions completed in 12.75 seconds. Head validation
  already downloads and replays the selected publisher's complete certified
  event history, so recovery no longer performs a redundant post-adoption tail
  request before shard work. The production recovery allowance is two minutes,
  covering the observed evidence ingestion plus reconstruction while focused
  tests retain the individual request and abandoned-request bounds.
- [x] **M5-31 / P1 — Reconcile request state after composite connection rejection.**
  The next fresh gate passed the repeated multi-owner production scenario,
  including three-holder cold recovery, in 3,281.88 seconds. Its process test
  then passed both small backups, the interrupted large backup, owner and
  storage-only seed recovery, and reached the isolated topology backup. Under
  concurrent relay load, the connection-limits behaviour rejected replacement
  connections after the earlier request-response behaviour had preloaded them.
  When the Swarm later reported its last live connection closed, the vendored
  request-response code retained one of those uncounted entries and aborted
  both the coordinator and hole-punched daemon on a debug assertion. Treat the
  Swarm's zero remaining-connection count as authoritative, drain every stale
  entry, and emit a typed `ConnectionClosed` failure for all of its pending
  requests. A later close for already reconciled state is harmless. The focused
  vendor regression covers outbound work on the real closed connection,
  inbound work on the stale connection, full cleanup, and a duplicate close.
- [x] **M5-32 / P2 — Give both isolated-topology backups the measured bound.**
  The corrected gate passed the repeated multi-owner production scenario in
  3,244.68 seconds. Its fresh process test passed onboarding, both small
  backups, the interrupted large backup, owner and storage-only seed recovery,
  and the first isolated-topology backup. All five topology daemons remained
  alive through the connection-rejection trigger, proving M5-31. That
  512,031-byte backup committed after about 70 minutes, but the immediately
  following 512,047-byte relay-fallback backup still used a legacy 180-second
  CLI allowance and timed out with healthy durable work in progress. Both
  constrained-topology backups now use the same measured ninety-minute bound;
  durable failures still return immediately.
- [x] **M5-33 / P1 — Scale relay capacity with the configured node budget.**
  The fresh process gate passed onboarding, both small backups, interrupted
  large-backup resume, both seed-recovery roles, and the first isolated
  topology backup in about 76 minutes 50 seconds. The relay-fallback backup
  then timed out after its full ninety-minute allowance. All five daemons were
  still alive and writing durable state, but the coordinator retried the same
  activation while the relay denied required circuits with `resource limit
  exceeded`. Relay service still inherited the fixed five-node beta caps of
  five reservations, eight circuits, and two circuits touching one peer even
  though dynamic guilds permit up to 256 members and the daemon already has an
  operator-set connection budget. Reservation and circuit totals, including
  the per-peer circuit allowance needed by a coordinator, now use
  `max_connections`; guild-only admission and the per-circuit byte and duration
  bounds remain. The vendored relay also enforces configured per-peer maxima at
  equality instead of admitting one extra reservation or circuit. Focused
  relay regressions, the complete locked all-target workspace tests, and
  warning-free locked all-target Clippy pass locally.
- [x] **M5-34 / P1 — Do not apply public-relay time throttles to authenticated guild traffic.**
  A fresh 10,391.43-second process run passed onboarding, both small backups,
  interrupted large-backup resume, both seed-recovery roles, and its first
  isolated-topology backup in about 44 minutes 45 seconds. The relay-fallback
  backup then used its complete ninety-minute allowance while all five daemons
  remained alive, transferred application bytes, and wrote durable state. The
  relay still inherited libp2p's public-service rate limiters, however: one new
  circuit per source peer every two minutes and one per source IP every minute.
  Those fixed windows returned `resource limit exceeded` during legitimate
  guild coding and cleanup retries, so the backup could not commit. Relay
  reservations and circuits now use replaceable guild membership as their sole
  source-admission limiter; configured reservation/circuit totals, per-peer
  reservation isolation, and circuit byte and duration bounds still constrain
  resources. A regression admits 64 immediate requests from one member through
  both limiter lists and continues to reject a nonmember.
- [x] **M5-35 / gate — Run the corrected production gate.**
  The ignored repeated multi-owner QUIC test had a stale checkpoint-version
  assertion, now corrected to version 7. Successive reruns exposed M5-04,
  M5-05, M5-06 after the catalog and local restore assertions passed, and M5-07
  when the daemon peer-exchange task first ran beside backup. The next run
  completed checkpoint 4 and exposed M5-08 at DHT readiness. Running the real
  publication loop throughout the next gate exposed M5-09 in bundle validation.
  The following run passed final-checkpoint readiness but exposed M5-10 when
  cold recovery applied an older, narrower copy of the same validation rule.
  The next run exposed M5-11 when its fixed watcher-startup sleep lost a race
  with capture after the full coding workload completed. The following run
  completed all 51 transcripts and exposed M5-12 when cold-recovery pinning
  consulted local dynamic state before the certified downloaded state had been
  adopted. The next run passed that transition and installed all recovered guild
  history and transcripts, then exposed M5-13 because serial transcript fetches
  consumed the recovery deadline before any shard was staged. The following run
  completed the same production workload but exposed M5-14: parallelizing each
  candidate's transcript list allowed redundant and offline candidate fetches
  to consume the complete global outbound budget before any certified state was
  adopted. The next run passed head certification and exposed M5-15 after two
  variable groups: unlike legacy recovery, variable recovery kept issuing a
  request to a deferred holder even when exactly `k` preferred holders remained,
  so abandoned requests again consumed the global budget. The following run
  installed all 51 transcripts and proved that selection correction, but
  exposed M5-16 because 21 independent local shard reconstructions still ran
  strictly serially inside the same 60-second recovery bound. The next run
  proved bounded concurrent reconstruction but exposed M5-17: a two-group
  pipeline activated only five of 21 shards because it still underfilled local
  reconstruction and durable activation work behind the globally bounded
  network fetches. Durable resume profiling then exposed M5-18: recovery
  repeatedly replayed already verified coding proofs and the complete authority
  history during adoption, planning, staging, and activation, consuming almost
  the whole bound even when shard data was already present. The corrected run
  then completed cold recovery inside the bound and exposed M5-19 when local
  installed-state resume replayed that same 59-event history under a one-second
  offline deadline. The next clean run verified and pinned its recovery head
  but exposed M5-20 before state adoption: redundant DHT endpoint-record
  refreshes consumed the remaining bound despite already validated locator
  endpoints. The following run passed cold recovery and the offline local
  resume, then exposed M5-21 when P2P shutdown returned before a detached
  inbound worker released the recovered node's directory lock. The next clean
  run exposed M5-22 when one delayed guild-event-tail request blocked every
  node's recovery-key reconciliation behind the request's 90-second logical
  deadline. The corrected 2,521-second production scenario passed all of its
  recovery and shutdown checks, then exposed M5-23 in the next process test's
  stale fixed-size guild-status assertion. Continuing that process test exposed
  M5-24 when initial recovery registration and the first coding activation
  divided the unanimous signatures for one sequence, leaving both proposals
  below quorum. After that ordering correction, the first backup passed and the
  healthy second backup exposed M5-25 by outliving the process test's legacy
  120-second coding bound. Continuing through the large interrupted backup
  exposed M5-26 when a pre-backup lifecycle signature lock and already retried
  coding attempts could not converge after coordinator restart. The next fresh
  run exposed M5-27 when the resulting backup fence also rejected the writer
  rotation owned by the same pending job. That run then passed the interrupted
  large backup and cold-recovery setup before exposing M5-28: the isolated
  topology backup's three-minute bound predated production delegated coding.
  The next fresh process run completed its first constrained-topology backup
  but exposed M5-33 when the relay's fixed-profile capacity made the required
  fallback route permanently unavailable. After M5-33 raised relay capacity,
  the next fresh run reached that route substantially faster and kept useful
  work moving for the complete timeout, but exposed M5-34 when inherited
  public-relay time windows throttled authenticated guild circuit churn. The
  corrected tree at `3d0bdbf` passed the complete local gate on 2026-09-18.
  A fresh `network-smoke.sh` run passed the five-daemon process scenario in
  9,288.94 seconds: both small backups, interrupted large-backup resume, owner
  and storage-only seed recovery, and both isolated topologies committed. The
  512,031-byte topology backup took about 75 minutes 9 seconds; the decisive
  512,047-byte relay-fallback backup committed in about 40 minutes with three
  simultaneous relayed peers and zero `resource limit exceeded` denials. A
  second fresh Btrfs image passed every preceding `reflink-acceptance.sh`
  command: all 19 provisioned filesystem/metadata/headroom tests, five-active-
  node seed recovery in 51.95 seconds, signed network commit/recovery in 94.76
  seconds, and repeated multi-owner QUIC backup/recovery in 2,796.81 seconds.
  Formatting, the complete locked all-target workspace suite, and warning-free
  locked all-target Clippy also pass. All compilation and execution were local;
  no remote compilation server was used.

- [x] **M5-36 / P1 — Authenticate packed contents against owner-signed source roots.**
  `GuildCheckpoint::validate` checks catalog source identities and aggregate
  lengths, without relating slot contents to the original `SectorRef.root`
  (`crates/mb-core/src/model.rs:847`). Format-7 signing skips original-sector
  coverage and checks RS transcripts for the coordinator-selected packed
  descriptors instead (`crates/mb-node/src/node.rs:5588`, `:5606`). The local
  durability check visits only legacy groups, which production clears
  (`node.rs:6038`; `network/p2p.rs:11459`). A faulty or malicious coordinator
  can retain an authentic revision, label different ciphertext with its source
  IDs, and obtain honest coding and checkpoint signatures. Restore discovers
  the mismatch only when checking the reconstructed original root
  (`network/p2p.rs:10555`); the certified backup can therefore be unrestorable.
  Require authenticated source-to-packed-content evidence before signing,
  preserved through recovery and repair. Gate with substituted source bytes
  under authentic IDs and valid packed roots/RS transcripts; reject before
  checkpoint approval, including when the original owner is absent.
  New user revisions sign an ordered Merkle commitment for every encrypted
  source sector while version-three revisions keep their original canonical
  encoding. Version-two packed catalogs carry compact aligned subtree proofs;
  validation authenticates each proof against the matching signed commitment
  and recomposes every packed-sector commitment from its ordered slot roots.
  Recovery and repair retain the proof table inside the certified catalog.
  Focused regressions reject substituted source bytes even after recomputing a
  self-consistent packed payload, catalog, and roots, without consulting the
  source owner. Core tests and the complete local node library suite pass.
- [x] **M5-37 / P1 — Apply dynamic quorum and recovery rules to every supported checkpoint version.**
  `QuorumCheckpoint::verify` honors `authority.quorum` only for version 5;
  versions 6 and 7 fall back to every member (`crates/mb-core/src/model.rs:1099`).
  Production creates version 7 and gathers policy-authorized signatures, then
  fails certificate verification if any nonrequired member is unavailable
  (`crates/mb-node/src/network/p2p.rs:11556`, `:11601`). After correcting that
  branch, `install_recovered_checkpoint` still rejects a recovering member
  who did not personally sign (`node.rs:7720`), although the core recovery rule
  explicitly permits this for authority-bearing versions (`model.rs:1159`).
  Preserve legacy unanimous rules while applying certified policy consistently
  to versions 5–7 and their cold-recovery paths. Gate majority/threshold commit
  with an absent nonrequired member and seed-only recovery of that nonsigner.
  `QuorumCheckpoint` now centralizes member recovery authorization and applies
  the configured policy to every authority-bearing format. Locator validation,
  dynamic-state adoption, DHT publication, cold installation, and local resume
  all use that same rule. The core version matrix proves legacy unanimity plus
  majority authorization and nonsigner recovery for formats 5, 6, and 7;
  focused core, node recovery-pinning, and DHT-publication tests pass locally.
- [x] **M5-38 / P1 — Resume the exact durable proposal for explicit recovery-key rotation.**
  `guild rotate-recovery-key` generates a fresh randomized envelope on every
  call (`crates/mb-node/src/network/p2p.rs:7488`). If the first call signs
  locally but fails to collect quorum, the next call proposes different bytes
  at the same sequence and conflicts with the durable signature lock
  (`node.rs:2383`). The registration reconciler only handles members with no
  current key (`network/p2p.rs:7017`), and lifecycle reconciliation leaves this
  locked event alone (`:7106`). For an already registered member, an ordinary
  quorum outage can thus leave rotation and subsequent guild writes stuck
  across restart. Reuse and resume the persisted rotation proposal without
  weakening anti-equivocation. Gate partial signing, quorum failure, repeated
  CLI retry, restart, and eventual rotation followed by backup.
  Explicit rotation preparation now loads the signature-locked proposal at the
  next sequence instead of generating another envelope. Periodic recovery-key
  reconciliation also resumes a locked local rotation before deciding that a
  current key needs no work. The active-guild regression locks an incomplete
  proposal, verifies byte-identical CLI preparation, commits that proposal,
  exercises automatic completion of another locked rotation, and proves a
  further proposal remains byte-identical after reopening the node.
- [x] **M5-39 / P1 — Do not let an empty event tail win synchronization.**
  The M5-22 shortcut accepts the first valid tail and abandons the other
  requests even when it contains no events
  (`crates/mb-node/src/network/p2p.rs:7636`). Empty tails from a peer at the
  caller's head are valid. Two lagging peers on a consistently faster path can
  keep selecting each other and never install certified events available from
  slower reachable peers. Membership, revocation, recovery-key registration,
  and coding activation can stop converging. Select a tail that advances the
  local state, without reinstating an all-peer wait; retain bounded fallback
  if its source cannot supply required coding evidence (`:7651`). Gate a fast
  empty responder, a slower advancing responder, and a selected source whose
  transcript request fails.
  Tail selection now treats an empty valid response as a bounded five-second
  fallback rather than success, so an advancing response can win without an
  all-peer logical-timeout wait. Coding-event evidence requests run concurrently
  across the eligible roster; invalid or unavailable sources are skipped until
  one transcript validates and installs. Focused asynchronous regressions cover
  the fast-empty/slow-advance deadline and unavailable plus invalid transcript
  sources before a valid fallback.
- [x] **M5-40 / P1 — Isolate unavailable roots in automatic scheduling and watching.**
  Roots are UUID-sorted and `next_dirty_root` always chooses the first dirty
  one (`crates/mb-node/src/node.rs:1004`, `:1410`). A failed scan of that root
  sets the global retry state and returns without considering another root
  (`:1317`). A missing or unreadable first root therefore indefinitely starves
  healthy dirty roots. `watch_once` also opens all roots as one fallible
  collection (`crates/mb-node/src/watcher.rs:82`), so one absent root prevents
  watches on every other root. Keep failure/backoff and watch recovery per
  root, select eligible roots fairly, and bind submission to the selected
  root. Gate an unavailable first root beside a healthy dirty root: the latter
  must remain watched and commit automatically before the former returns.
  Automatic polling now stores sorted per-root retry records, scans past roots
  in backoff, and returns the selected root UUID with its estimate; submission
  uses that exact UUID. Non-capacity submission and job failures also back off
  only the affected root. The watcher attaches, health-checks, detaches, and
  exponentially retries each root independently while its healthy siblings
  remain live. Focused tests prove an unavailable lower-UUID root does not
  prevent selection of the healthy root and that a real filesystem event on
  the healthy root is persisted while its sibling path is absent.
- [x] **M5-41 / P1 — Release failed relay reservation admissions and permit full-capacity renewal.**
  Relay admission inserts a reservation before its acceptance response
  succeeds, but `ReservationReqAcceptFailed` does not undo the insertion
  (`vendor/libp2p-relay/src/behaviour.rs:452`, `:494`). The handler starts the
  expiry timer only on success (`src/behaviour/handler.rs:836`). With M5-33's
  one-reservation-per-peer cap enforced at equality, a reset acceptance stream
  leaves an unexpiring slot while the connection survives; later requests on
  that connection are new reservations and are rejected. The client reuses
  the connection, so periodic listener retries cannot repair relay-only
  reachability. Roll back failed first accepts without dropping a previously
  active reservation. Also exempt true renewals from the total-new-reservation
  cap (`behaviour.rs:427`). Gate failed acceptance followed by successful retry
  on the same connection at per-peer cap 1, and renewal at full global capacity.
  The relay now distinguishes provisional new reservations from established
  ones. A failed first acceptance removes only its provisional `(peer,
  connection)` slot, while failed renewal preserves the established
  reservation. New-reservation capacity checks no longer apply to renewals.
  Focused vendored-relay regressions cover slot release at per-peer cap 1 and
  renewal failure while both peer and global capacity are full; all relay
  library tests pass locally.
- [x] **M5-42 / P2 — Reconcile tentative request connections on rejection itself.**
  Request-response records a connection before the later composite connection
  limiter accepts it (`vendor/libp2p-request-response/src/lib.rs:818`;
  `crates/mb-node/src/network/p2p.rs:441`). A rejected established handshake
  yields `DialFailure` or `ListenFailure`, without a `ConnectionClosed` event.
  Neither failure path removes the tentative `connected` entry (`lib.rs:783`,
  `:915`). M5-31 only drains stale entries after an accepted connection to the
  same peer closes with zero remaining (`:736`), which never happens for peers
  having only rejected connections. Repeated denied handshakes under fresh
  identities can grow this map beyond `max_connections`; requests preloaded
  into rejected handlers can also remain pending. Clean up the exact denied
  connection and its work on both failure paths. Gate repeated inbound and
  outbound denials with no accepted connection and with a surviving sibling.
  Request-response now removes the exact tentatively tracked connection on
  both `DialFailure` and `ListenFailure`. Its preloaded inbound and outbound
  work receives terminal failure events, while any accepted sibling remains
  tracked. Focused regressions alternate repeated denials under fresh peer
  identities without map growth and verify exact cleanup beside a surviving
  connection; the vendored library tests and strict clippy pass locally.
- [x] **M5-43 / P2 — Make small production updates incremental in data and resource cost.**
  Snapshot capture assigns every data sector an ID derived from the new
  revision UUID (`crates/mb-node/src/snapshot.rs:729`;
  `crates/mb-core/src/content.rs:37`), which also changes its encryption nonce.
  Unchanged file bytes therefore become new source IDs/ciphertext and need new
  packing/coding; stable slots only preserve IDs from retained old revisions
  (`crates/mb-core/src/packing.rs:475`). Additionally, every backup refetches
  every distinct source sector referenced by retained revisions before
  considering its prior packed copy (`crates/mb-node/src/network/p2p.rs:11189`),
  materializes the full input set, and rewrites all packed payloads
  (`node.rs:3309`). A no-change or single-byte update has work proportional to
  retained data, including network transfer for sources on other members.
  Preserve authenticated references for unchanged data, reuse unchanged packed
  payloads before remote fetch, and bound packing memory and durable writes to
  appropriate batches. Gate no-change and one-chunk updates over a large
  retained multi-owner corpus, asserting actual source reads, transferred
  bytes, new coding work, peak memory, and durable bytes rather than only old
  slot positions. Preserve safe encryption nonce use when changing identities.
  Revision capture now derives sector IDs from owner, guild, purpose, logical
  length, and plaintext, so a nonce is reused only for identical plaintext
  under the same guild key. A metadata-only catalog advance handles no-change
  revisions with no source reads, packed writes, or new coding descriptors.
  Changed revisions fetch only source objects absent from the prior authenticated
  catalog. The incremental packer retains prior proofs and descriptors, loads
  only packed sectors whose slots change, and durably emits only those sectors.
  Its metrics expose transferred source bytes, changed coding sectors, packed
  durable bytes, and peak materialized payload. Focused large multi-owner
  coverage proves a one-source addition remains below retained-corpus reads and
  memory while unchanged descriptors remain byte-identical; strict clippy and
  core tests pass locally.
- [x] **M5-44 / P2 — Integrate fair information placement and reusable coding geometry.**
  Production assigns every packed information sector to the checkpoint
  coordinator and passes no other candidate information into the lane builder
  (`crates/mb-node/src/network/p2p.rs:11494`, `:11525`). Each group consequently
  has one real input; for the five-domain 3+2 profile, the other two information
  rows are virtual zero even with abundant multi-user data (`:10945`, `:10773`).
  The coordinator keeps the entire packed corpus in `control.db`
  (`node.rs:3313`), outside the parity placement admission path, and placement
  hashes each revision/sector ordinal separately (`network/p2p.rs:10730`).
  This does not implement the planned fair, capacity-aware information hosts
  and reusable geometry for adjacent ranges. Place and account for packed
  information across eligible failure domains, fill real information lanes
  when available, and persist geometry reusable across bounded runs. Gate a
  multi-owner workload with enough real inputs, a coordinator with limited
  storage, per-member information/parity accounting, and explicit storage and
  transfer amplification bounds. Production now batches adjacent uncovered
  packed sectors into full real-information lanes and selects distinct,
  reachable information holders by available capacity and balanced assignment.
  Information and parity placements debit one shared capacity view. The
  checkpoint coordinator stages each packed input once, serves locally held
  inputs directly to its coder, and removes its packed payload cache after the
  checkpoint finalizes; later incremental updates fetch only prior packed
  sectors whose slots change from their certified holders. Attempt staging is
  resumable and cleaned up on failure, local assignments activate on configured
  storage volumes, and unchanged descriptors retain their existing certified
  groups. A six-domain, nine-sector regression fills all three information rows,
  limits the coordinator to one stored shard, checks all 15 information/parity
  capacity debits, and proves deterministic geometry on a repeated bounded run.
  The full `mb-node` library suite passes locally (222 passed, 10 provisioned
  tests ignored), as does strict package Clippy.
- [x] **M5-45 / gate — Recheck the corrected tree before closing Milestone 5.**
  Close M5-36 through M5-44 with focused source review and the regressions
  described above. Then run the required formatting, locked workspace tests,
  warning-free Clippy, and provisioned filesystem/network acceptance locally.
  Include adversarial packed-source substitution, nonunanimous checkpoint and
  seed recovery, interrupted explicit rotation, lagging-peer convergence,
  root failure isolation, rejected connection/reservation lifecycles, and
  measured incremental/placement efficiency. Prior happy-path gate results do
  not replace this evidence. No build or runtime checks were run in this
  source-only review. The first corrected-tree provisioned run exposed two
  duplicate-content assumptions after M5-43 made sector IDs content-derived:
  the legacy signed-network fixture coded repeated IDs more than once, and
  recovered-anchor validation rejected repeated signed references even when
  every distinct ID matched exactly. The fixture now protects each distinct
  sector once and restore accepts repeated identical references while retaining
  exact per-ID checks. The formerly failing signed network commit and seed
  recovery scenario passes on the provisioned Btrfs filesystem. The
  multi-owner production assertion now checks exact active coverage, bounded
  three-input group count, and actual multi-input use instead of requiring the
  obsolete one-group-per-sector layout; its full real-QUIC scenario passes.
  The final committed tree passes `cargo fmt --all -- --check`,
  `cargo test --locked --workspace --all-targets`, and
  `cargo clippy --locked --workspace --all-targets -- -D warnings`. A fresh
  locally provisioned 2 GiB Btrfs image also passes the complete
  `scripts/reflink-acceptance.sh` gate: all provisioned anchor/reflink,
  interruption, headroom, relocated recovery, five-node seed recovery, signed
  network recovery, repeated multi-owner QUIC, and five-daemon namespace/NAT/
  DHT recovery scenarios pass. All compilation and execution were local; no
  remote compilation server was used.

- [x] **M5-46 / P1 — Make quorum checkpoint completion recoverable and convergent.**
  Production accepts finalization on exactly the configured quorum
  (`crates/mb-node/src/network/p2p.rs:12191`, `:12282`) and sends the
  certificate only to its signers (`:12238`, `:12243`). With a five-member
  majority, three current holders can commit, but each has only two other
  current publishers while seed recovery requires three
  (`crates/mb-node/src/node.rs:7690`; `network/p2p.rs:8745`). An active member
  that misses that certificate also has no ordinary catch-up path: normal
  storage requires its own signature (`node.rs:5700`), and its stale head
  prevents signing the next generation (`:6136`). Align commit durability with
  the recovery publisher rule, durably disseminate certified heads, and let
  nonsigning active members catch up without erasing state or weakening
  authorization. Gate the minimum policy quorum, failed finalization, a later
  rejoin, loss of each finalized member, seed recovery, and a subsequent
  checkpoint.
  Certificate staging and finalization now target all reachable active members,
  including nonsigners. Completion requires the policy quorum and up to four
  durable holders, which leaves the three independent publishers required by
  five-member seed recovery after any holder loses its copy. A quorum-certified
  checkpoint may be stored without a local signature but must extend the exact
  local head. Peer exchange advertises signed head locators and walks a bounded,
  verified parent chain so a rejoining member converges before later signing.
  Focused recovery/wire tests and strict node Clippy pass locally.
- [x] **M5-47 / P1 — Let slow advancing event tails beat fast empty peers.**
  The event synchronizer starts a fixed five-second deadline after any valid
  empty response and cancels every still-pending request when it expires
  (`crates/mb-node/src/network/p2p.rs:110`, `:7724`). A reachable relay or Tor
  path may legitimately take longer than that while request and logical
  deadlines are 20 and 90 seconds (`:113`, `:114`). Fast lagging peers can
  therefore keep a member permanently behind despite a reachable advancing
  peer. Preserve bounded progress without discarding the only advancing
  request on every pass. Gate repeated fast-empty responses beside an
  advancing response arriving after five seconds on a supported slow path.
  Empty tails now leave outstanding paths alive for the full 90-second logical
  request lifetime. The selector therefore accepts a later valid advancing
  tail while retaining a hard bound for stalled peers. The scaled slow-path
  regression and strict node Clippy pass locally.
- [x] **M5-48 / P1 — Debounce and schedule automatic backups per protected root.**
  Every changed root rewrites one global quiet-period timestamp
  (`crates/mb-node/src/node.rs:1138`, `:1166`), while eligible roots are scanned
  in UUID order and the first is selected (`:1004`, `:1389`). A continuously
  changing root can postpone every sibling forever; once the quiet period is
  reached, a repeatedly dirty lower UUID can still starve later roots. Persist
  root-scoped debounce/attempt state and fair or oldest-eligible selection.
  Gate a noisy lower-UUID root beside a quiet dirty root and prove the quiet
  root commits within a bounded interval while both remain watched.
  Durable automatic-backup state now records each dirty root's quiet timestamp
  and last attempt independently. Polling migrates legacy global state, orders
  eligible roots by oldest dirty time, and removes schedules as roots become
  clean. A restart regression proves repeated changes to a lower-UUID root do
  not delay its quiet sibling; all automatic-backup tests and strict node Clippy
  pass locally.
- [x] **M5-49 / P1 — Scope stable source identities and recipes to protected roots.**
  Content-derived sector IDs omit the protected-root UUID
  (`crates/mb-core/src/content.rs:55`), but checkpoint validation rejects one ID
  when it appears under two roots (`crates/mb-core/src/model.rs:819`). Identical
  chunks in ordinary independent roots therefore prevent checkpoint creation.
  Local recipes are also keyed only by sector ID
  (`crates/mb-node/src/snapshot.rs:799`), so relaxing validation alone would let
  one root overwrite another root's anchor locator and later GC its backing
  anchor. Make identity, recipe ownership, and anchor lifetime root-safe. Gate
  identical content across two roots through repeated backup, independent
  retention/GC, and restore of both roots.
  Revision format 5 now includes the protected-root UUID in each stable content
  ID. Equal bytes in separate roots therefore have separate sector/recipe keys,
  while equal bytes within one root retain stable reuse. Formats 3 and 4 retain
  their canonical decoding and restore behavior. Core coverage proves root
  separation and format-4/format-5 round trips.
- [x] **M5-50 / P1 — Key stable sector IDs against plaintext guessing.**
  `make_content_sector_id` hashes plaintext with only public owner, guild,
  purpose, length, and constant-domain inputs
  (`crates/mb-core/src/content.rs:55`). IDs are published in replicated signed
  revisions, so a guild peer can confirm guesses for short or low-entropy
  private content without the owner's encryption key. Derive stable IDs with
  owner-secret key material as well as protected-root scope, retain stable
  reuse for identical content in the same root, and version the migration.
  Gate direct dictionary guesses against observed revision IDs.
  `KeyMaterial::guild_content_id_key` derives a separate owner-secret key, and
  the version-2 content-ID hash uses it before hashing the public scope and
  plaintext. Tests prove that equal public inputs under another owner secret
  do not reveal the same ID. The full core suite and strict core/node library
  Clippy pass locally.
- [x] **M5-51 / P1 — Reject unauthenticated catalogs in newly signed format-7 checkpoints.**
  Current model validation expressly accepts a version-one packed catalog with
  no source authentication (`crates/mb-core/src/model.rs:916`), and checkpoint
  signing relies on that validation while checking coding only for the supplied
  packed descriptors (`crates/mb-node/src/node.rs:5730`, `:5825`). Transition
  validation checks catalog sequence and parent but permits a version-two to
  version-one downgrade (`:6167`). A coordinator can thus recreate M5-36 by
  coding self-consistent substitute bytes under authentic source identities and
  obtaining honest checkpoint signatures. Keep historical version-one decoding
  separate from authorization of a new checkpoint and forbid authentication
  downgrade. Gate a commitment-bearing revision with a newly proposed
  unauthenticated catalog and a v2-to-v1 transition.
  Checkpoint signing now applies a current-format authorization gate after
  structural validation: every newly signed format-7 body must carry a
  root-bound version-3 or migration version-4 authenticated catalog.
  Historical version-1 and version-2 catalogs remain decodable and verifiable
  for recovery, but cannot be signed into another current checkpoint or
  accepted as a downgrade. The focused node regression, complete core suite,
  and strict core/node library Clippy pass locally.
- [x] **M5-52 / P1 — Migrate retained legacy revisions through authenticated packing.**
  Version-three revisions remain valid and readable without signed source
  commitments, but production packing requires commitments on every retained
  revision (`crates/mb-node/src/network/p2p.rs:11631`). The backup path retains
  prior per-root history and then unconditionally invokes that packer
  (`:12064`, `:12102`); the default retention is 30
  (`crates/mb-node/src/node.rs:1666`). An existing guild cannot commit its first
  post-upgrade backup, and retention one cannot atomically solve a multi-owner,
  multi-root history. Add an explicit authenticated migration or compatibility
  path that keeps old committed layouts recoverable until retirement. Gate an
  upgrade from a legacy format-7 head, another backup by each owner/root, and
  restore of both legacy and new retained revisions.
  Catalog version 4 now carries owner-signed migration bindings from each
  retained legacy revision's signed flat root to its source Merkle commitment.
  Production obtains a binding once, verifies both hashes against the source,
  reuses it from later catalogs, and can recover unavailable source bytes from
  the prior packed layout. Checkpoint validation requires an exact binding for
  every legacy authenticated source and rejects mismatches or unused bindings.
  Core migration/serialization/checkpoint regressions, focused node binding
  and catalog-advance regressions, and strict core/node library Clippy pass
  locally.
- [x] **M5-53 / P1 — Reconstruct prior packed sectors from any surviving `k` shards.**
  Incremental repacking selects a packed sector's assigned information holder
  and reads only that holder (`crates/mb-node/src/network/p2p.rs:11857`), even
  though restore already has an any-`k` reconstruction path (`:10575`). This
  loader serves changed-slot updates and replacement staging, after the
  coordinator deletes its finalized packed cache. One unavailable or removed
  information holder can therefore block a small update and the recoding meant
  to replace it despite enough surviving information/parity shards. Reuse the
  bounded reconstruction path with commitment checks. Gate incremental update
  and member replacement with the assigned holder absent and each valid set of
  `k` surviving shards.
  The distributed packed-sector loader now invokes the same bounded variable
  shard reconstruction used by restore. It first tries the assigned holder,
  then fetches any sufficient information/parity set, verifies the reconstructed
  Merkle commitment, and finally checks both catalog roots. Focused recovery and
  packed-lane regressions plus strict node Clippy pass locally.
- [x] **M5-54 / P1 — Bind each packed flat root to its authenticated bytes.**
  Catalog authentication recomposes the Merkle commitment from owner-signed
  source proofs but does not bind `descriptor.flat_root` to that commitment
  (`crates/mb-core/src/packing.rs:301`). Coding copies the asserted flat root
  into the coordinator's plan, and checkpoint coverage checks only that the
  transcript repeats it (`crates/mb-node/src/node.rs:5853`). A malicious packed
  coder can protect the correct Merkle-authenticated bytes under a false flat
  root and still obtain honest transcript/checkpoint signatures; restore then
  rejects those certified bytes because it checks both roots (`packing.rs:1136`).
  Remove the redundant root or add independently verifiable binding evidence.
  Gate a false-flat-root plan with valid source proofs, Merkle openings, parity,
  and verifier transcript, rejecting it before checkpoint signature.
  Authenticated catalog versions 3 and 4 now define the canonical packed root
  as the already authenticated Merkle commitment root and reject any unequal
  `flat_root`. Current checkpoint signing admits only those root-bound catalog
  versions, while historical versions 1 and 2 remain readable. Coding accepts
  the Merkle root as its information root, and focused catalog, coding, and
  checkpoint tests reject substituted or mismatched roots. The complete core
  suite and strict core/node library Clippy pass locally.
- [x] **M5-55 / P1 — Plan feasible multi-lane placement without greedy capacity fragmentation.**
  Information and parity selection treat every positive remaining capacity
  alike (`crates/mb-node/src/network/p2p.rs:10897`, `:11098`) and plan/debit
  lanes sequentially without look-ahead or backtracking (`:11163`). A two-lane
  `3+2` workload over six domains with capacities `1,1,2,2,2,2` has an exact
  feasible allocation, but a first lane that consumes both one-slot domains
  leaves only four domains and aborts the second lane. Use a bounded planner
  that preserves enough distinct future domains while maintaining fairness.
  Gate fragmented feasible capacities for initial production and replacement
  coding, plus a truly infeasible control case.
  Packed placement is now planned over the complete ordered lane run. A
  Havel-Hakimi-style highest-remaining-domain allocation preserves capacity for
  later lanes, selects an actual holder within each domain, and forces both the
  planned information and parity roles into geometry construction. The exact
  `1,1,2,2,2,2` case succeeds and a nine-slot control fails as infeasible.
- [x] **M5-56 / P2 — Build and reuse coding geometry over adjacent packed ranges.**
  `build_packed_coding_lanes` sorts descriptors by content-derived sector ID
  before chunking (`crates/mb-node/src/network/p2p.rs:11153`), so its lanes are
  unrelated to canonical catalog `sector_index`. It also derives each new
  lane's placement independently rather than reusing a compatible adjacent
  run. This contradicts M5-44's claimed adjacent batching and prevents the
  planned range coalescing. Order by catalog range, reuse exact compatible
  holder geometry across bounded runs, and gate descriptors whose ID order
  differs from index order across an incremental update.
  Lane input is now ordered by canonical `sector_index`, with a regression that
  reverses ID/input order and still obtains adjacent ranges. Exact compatible
  holder geometry is now preferred from the preceding lane whenever the
  whole-run capacity plan permits it. Regressions prove stable adjacent holder
  layouts and repeatable geometry; strict node Clippy passes locally.
- [x] **M5-57 / P1 — Serialize relay reservation admission, acceptance, and expiry.**
  A first reservation is inserted before its acceptance settles
  (`vendor/libp2p-relay/src/behaviour.rs:346`). An overlapping request at the
  per-peer cap can replace and drop that acceptance future in the handler, but
  its denial never clears the first provisional slot; provisional entries are
  also visible to circuit routing before acceptance. Separately, expiry can
  remove a renewal's old slot before its pending success event blindly
  reinserts it, exceeding full global capacity. Separate provisional admissions
  from established reservations or otherwise make these transitions atomic.
  Gate overlapping first requests on one connection, circuit traffic before
  acceptance, and timeout-before-renewal-success while another peer fills the
  last slot.
  The vendored relay now queues reservation response futures per connection and
  tracks provisional admissions separately from established reservations.
  Capacity counts both without double-counting renewals; expiry removes circuit
  eligibility but retains a pending renewal's capacity claim until success or
  failure. Regressions cover overlapping first requests, provisional visibility,
  and expiry during renewal. All relay unit tests and strict relay Clippy pass.

- [x] **M5-58 / P1 — Let certified nonsigners adopt and publish checkpoints.**
  Certificate staging and peer catch-up both finish through `store_checkpoint`,
  but that path still passes `require_signature_lock = true`
  (`crates/mb-node/src/node.rs:5840`, `:5848`). The database consequently
  rejects a valid quorum certificate unless this node signed the exact body
  (`crates/mb-store/src/database.rs:958`). In a five-member majority, the two
  reachable nonsigners cannot become durable holders or later publishers, so
  the M5-46 availability correction does not work. Permit a verified certificate
  to atomically adopt the matching signature lock while retaining the exact-head
  and transition checks. Gate policy-quorum finalization to all reachable
  signers and nonsigners, loss of a signer, seed recovery, and the next
  checkpoint.
  Verified certificates now enter the same exact-head transition validation
  without requiring a local signature lock; the database atomically adopts the
  certified body as the new lock. A regression installs a majority certificate
  signed only by three remote members and confirms that the nonsigner becomes a
  durable holder across restart.
- [x] **M5-59 / P1 — Catch checkpoints up across historical authority epochs.**
  Peer exchange synchronizes guild events before checkpoints
  (`crates/mb-node/src/network/p2p.rs:7076`), then installs the checkpoint chain
  oldest first through `store_checkpoint` (`:7175`). That store requires current
  membership, so an intermediate checkpoint that was valid under a recorded
  earlier authority is rejected after the event head has advanced
  (`crates/mb-node/src/node.rs:5842`, `:6239`). Validate each certified link
  against its historical authority while keeping the final local authority
  current. Gate a lagging member from an authority-A checkpoint through an
  A-to-B event and B checkpoint without resetting local state.
  Checkpoint storage now accepts an authority found anywhere in the verified
  durable event history, and historical owner validation accumulates every
  roster rather than consulting only the newest one. The catch-up regression
  advances events from unanimous to majority authority before installing the
  earlier checkpoint, then reaches the current checkpoint normally.
- [x] **M5-60 / P1 — Keep clean roots out of dirty-root schedule lookup.**
  Polling retains and creates schedules only for dirty roots
  (`crates/mb-node/src/node.rs:1446`, `:1458`), but then filters every configured
  root and indexes the schedule map unconditionally (`:1491`). Once one root is
  committed and its schedule removed while a sibling remains dirty, the next
  poll panics on the clean root. Select only roots with a schedule and preserve
  root-local cleanup. Gate mixed clean/dirty roots after commit and after adding
  or restoring a clean root beside an existing dirty root.
  Eligibility now requires a root-scoped schedule before the sort or lookup, so
  clean configured roots never index the dirty schedule map. A mixed clean/dirty
  regression selects the dirty sibling and preserves exactly its one schedule.
- [x] **M5-61 / P1 — Apply the byte budget without starving eligible roots.**
  Automatic backup selects the oldest readable root and stops
  (`crates/mb-node/src/node.rs:1513`), then checks that root against the remaining
  daily byte budget (`:1566`). An oversized oldest root therefore blocks the
  whole window every day while smaller dirty siblings that fit are never
  considered. Include budget eligibility in the fair root selection and retain
  a root-scoped blocked reason for the skipped root. Gate an oversized oldest
  root beside smaller eligible siblings across consecutive budget windows.
  Byte-budget eligibility is now evaluated inside the oldest-first root scan.
  An oversized root receives a retry at the next window with its own reason,
  while later roots remain eligible; explicit block clearing also clears those
  root-local retries after a policy change. The regression proves that an
  oversized lower UUID cannot stop a fitting sibling. All seven focused
  automatic-backup tests and strict all-target node Clippy pass locally.
- [x] **M5-62 / P1 — Retire the final legacy binding without losing modern sources.**
  Once no legacy binding remains, production skips unchanged authenticated
  inputs (`crates/mb-node/src/network/p2p.rs:11936`), but the complete-corpus
  authenticated updater accepts only catalog versions 2 and 3 (`:12051`;
  `crates/mb-core/src/packing.rs:927`). A prior version-4 catalog therefore falls
  into `pack_incremental`, where the partial inputs are treated as the complete
  desired corpus (`packing.rs:743`) and retained modern sources disappear. If
  the source set is unchanged, cloning version 4 instead leaves now-unused
  bindings. Both paths fail catalog/checkpoint validation when the last legacy
  revision retires. Make version-4 retirement an authenticated complete-corpus
  transition that removes exactly obsolete bindings. Gate retention one and
  larger multi-owner histories through the final legacy retirement and another
  backup. The authenticated complete-corpus updater now accepts a validated
  version-4 predecessor and always emits a binding-free version-3 catalog.
  The unchanged fast path refuses to clone a version-4 catalog after the last
  legacy source retires, forcing that complete-corpus transition. Core and node
  regressions cover the version-4-to-version-3 transition and fast-path guard.
- [x] **M5-63 / P1 — Make legacy migration durable without every historical owner online.**
  A missing migration binding is obtained only from the exact source owner
  (`crates/mb-node/src/network/p2p.rs:11885`), whose signer reads its local sector
  (`crates/mb-node/src/node.rs:3570`). An offline or removed historical owner can
  thus block the first upgraded checkpoint even when the certified old layout
  has enough surviving shards. The acquired bindings are not persisted
  independently; `store_packing_result` stores only packed-sector records
  (`node.rs:3580`), so a crash before publication requires the owner again.
  Define a verifiable offline-owner migration path and durably journal accepted
  bindings before checkpoint publication. Gate migration with a retained owner
  offline or removed, any valid `k` old shards, and restart at every publication
  boundary. A missing owner binding now falls back to certified any-`k`
  reconstruction of the historical information shard. Current checkpoint
  members verify both the signed flat root and reconstructed Merkle commitment,
  then sign a guild- and membership-epoch-bound attestation. Version-5 catalogs
  carry a checkpoint-policy quorum of those attestations, and checkpoint
  validation rejects stale, nonmember, conflicting, insufficient, or unused
  evidence. Every accepted attestation is journaled before catalog/checkpoint
  publication and reused after restart. Core quorum/insufficiency, removed-owner
  quorum, and durable restart regressions pass locally.
- [x] **M5-64 / P1 — Use any-`k` packed recovery throughout the migration window.**
  While any legacy binding remains, production fetches every retained source
  (`crates/mb-node/src/network/p2p.rs:11941`). Its failure fallback checks only
  the coordinator's packed cache or locally assigned information shard
  (`:11958`), although finalization normally deletes that cache (`:12596`); it
  never reaches the distributed any-`k` loader at `:12142` because catalog
  version 4 is excluded from that updater. A changed backup is therefore blocked
  by any unrelated offline source owner or remote information holder despite
  enough surviving shards. Route version-4 source recovery through the bounded
  commitment-checked any-`k` loader. Gate one changed source with another owner
  offline, the assigned information holder absent, and each valid `k`-shard set.
  Version-4 updates now use the authenticated incremental updater. When a
  retained source cannot be read from its owner, every packed descriptor that
  contains it is loaded through the existing certified-placement any-`k`
  reconstruction path and checked against the catalog commitment before the
  source is unpacked. The same loader supplies changed packed sectors to the
  incremental updater.
- [x] **M5-65 / P1 — Bound and fairly drain relay reservation responses.**
  M5-57 replaced one response future with an unbounded per-connection `VecDeque`
  (`vendor/libp2p-relay/src/behaviour/handler.rs:358`). Every reservation
  decision appends a future that owns its request stream (`:510`), while only
  the front is polled and response I/O has no timeout (`:822`). Ready inbound
  workers are returned first (`:636`), and overlapping requests rejected by a
  provisional admission bypass both rate limiters through the capacity-check
  short circuit (`vendor/libp2p-relay/src/behaviour.rs:329`, `:505`). One peer
  can therefore replenish parsed requests, starve or stall the queue head, and
  grow daemon memory without bound. Cap outstanding reservation streams, apply
  admission/rate limits to overlaps, fairly poll responses, and time out or
  reset a blocked head. Gate sustained overlapping ingress plus a stalled first
  response and prove a fixed per-connection bound and continued progress. Each
  relay connection now admits at most ten reservation response futures, polls
  them independently ahead of new inbound work, and resets any response that
  has not completed within the stream timeout. Aborted accept responses release
  provisional reservation capacity. Capacity-rejected overlaps still consume
  configured peer/address rate-limit admission. Vendored relay regressions pin
  the queue bound, progress past a stalled response, and overlap rate accounting;
  all relay library tests and strict Clippy pass locally.
- [x] **M5-66 / P1 — Make bounded checkpoint-chain catch-up advance.**
  The new walker fetches a head and then requests each parent from the same peer
  (`crates/mb-node/src/network/p2p.rs:7142`), but a peer serves checkpoint pages
  only for its current head (`crates/mb-node/src/node.rs:9501`). A member two
  generations behind therefore cannot fetch the intermediate checkpoint unless
  another peer happens to retain it as its head. A gap over 1,024 is skipped
  before any checkpoint is stored (`p2p.rs:7137`), so every later pass repeats
  the same skip. Serve certified retained ancestors and make bounded passes
  durably advance instead of requiring the entire gap at once. Gate ordinary
  rejoin from generation G when all current peers are at G+2 and G+1025, with no
  intermediate-head peer, then finalize G+n+1 after convergence.
  Members now serve every retained verified checkpoint by hash. Catch-up stages
  a hash-linked generation index and cursor transactionally, fetches at most
  1,024 ancestors per pass, and installs at most 1,024 oldest certificates per
  pass. Both phases resume after restart. The regression covers a two-generation
  parent walk, bounded partial installation, restart, retained-ancestor paging, and
  final convergence without an intermediate-head peer. The complete node
  library suite (227 passed, 10 provisioned tests ignored) and strict all-target
  node Clippy pass locally.

- [x] **M5-67 / gate — Recheck the final corrected tree before closing Milestone 5.**
  The final source review found no blocker after M5-58 through M5-66. On
  2026-09-22 the exact corrected tree passed `cargo fmt --all -- --check`,
  `cargo test --locked --workspace --all-targets`, warning-free
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `scripts/docker-lab-safety-test.sh`. A fresh disposable local 2 GiB Btrfs
  image passed the complete `scripts/reflink-acceptance.sh` gate: all 12
  anchor/reflink cases, all seven node interruption/recovery/headroom cases,
  five-node seed recovery, signed network commit and recovery, repeated
  multi-owner QUIC backups, and five-daemon namespace/NAT/DHT recovery. The
  disposable filesystem was unmounted and removed afterward. All compilation
  and execution were local; no remote compilation server was used.

- [x] **M5-68 / P1 — Keep revoked historical authority out of the current checkpoint head.**
  Ordinary storage, signing, staged finalization, catch-up selection, and the
  final catch-up target now require current authority. Historical authority is
  available only inside an active catch-up state for a nonfinal exact-parent
  link. Legacy format-4 authority is current only in the initial unanimous
  membership epoch. The regression installs an A-authorized intermediate,
  rejects a late A successor as a target, and reaches a B-authorized head across
  restart.

- [x] **M5-69 / P1 — Validate historical checkpoint contents against their recorded epoch.**
  Historical coverage now replays every certified guild event from genesis,
  requires the checkpoint authority to occur in that history, and validates
  writer keys and coding groups against a matching historical snapshot. Current
  checkpoints retain current-writer/current-placement rules. Regressions cover
  writer rotation, quorum transition, coding-group retirement and forgetting,
  plus restart between intermediate installations.

- [x] **M5-70 / P1 — Reject or abandon poisoned checkpoint catch-up candidates.**
  Selection fetches the advertised certificate, verifies its installed genesis
  and current recorded authority, and persists its source with the target.
  Invalid higher candidates are skipped in the same pass. Missing quorum
  evidence, unavailable links, or failed installation clears the durable
  candidate before returning, while legacy staging state is discarded during
  resume. A fake or revoked roster cannot pin later synchronization across
  restart.

- [x] **M5-71 / P1 — Bound total checkpoint staging while advancing the durable head.**
  The peer protocol can request the accepted hash at one generation. Catch-up
  requires the current quorum minus the local member to endorse each nonfinal
  generation, fetches its certificate, and commits that exact-parent link
  immediately. Each pass remains capped at 1,024 links, durable state resumes
  at the next generation after restart, and persistent uncommitted certificate
  occupancy is zero. Head progress begins with the first successful link.

- [x] **M5-72 / P1 — Separate uncommitted catch-up certificates from finalized checkpoints.**
  Catch-up no longer persists certificate bytes before committing them; its
  durable namespace contains only cursor, target, and source metadata. Legacy
  generation staging is removed on resume without deleting accepted history.
  Staged finalization treats a pre-existing certificate as complete only when
  the exact certificate is both the durable head and signature lock. The race
  regression injects an uncommitted certificate into the old namespace and
  proves finalization refuses to acknowledge it.

- [x] **M5-73 / P1 — Refresh legacy evidence from the authenticated packed copy.**
  When direct owner access fails, evidence refresh now recovers the source from
  the previous authenticated catalog before falling back to an original-source
  coding placement. Packed descriptors are checked against their commitments,
  unpacking authenticates the requested source chunks, and the reconstructed
  sector is checked against both the signed flat root and derived source Merkle
  commitment before current members attest it. Thus an offline or removed
  legacy owner and a retired original group do not prevent a later
  membership-epoch refresh after restart while any valid packed `k` remains.

- [x] **M5-74 / P1 — Try every certified replacement placement during recovery.**
  Original-source and packed-sector recovery now collect every matching active
  certified group, sort current-geometry placements ahead of stale overlap,
  and try the bounded candidates in deterministic group order. A failed or
  commitment-conflicting reconstruction advances to the next placement; only
  a source-root-valid or packed-descriptor-valid reconstruction is accepted.
  Placement coverage verifies that a current replacement is preferred while
  the stale group remains available as a fallback candidate.

- [x] **M5-75 / P2 — Preserve incremental packing bounds through v4/v5 migration.**
  Metadata-only advancement now accepts v3-v5 predecessors and carries the
  exact current bindings or attestations, including refreshed epoch evidence
  and final evidence retirement. Each unchanged authenticated source is
  omitted independently from payload inputs, and core reuses identical v3-v5
  descriptors without loading their packed bytes. Evidence refresh retains a
  recovered legacy payload only when its authenticated commitment actually
  needs repacking, keeping unchanged large mixed catalogs bounded to the
  current source rather than the full corpus. No-change writes no packed
  sectors; one-source changes and final retirement touch only descriptors whose
  slot layout changes.

- [x] **M5-76 / P1 — Let relay reservation expiry preempt replenishable inbound work.**
  The handler now polls the active reservation timer before queued events,
  response futures, inbound workers, circuits, and outbound work. Once the
  deadline is ready, it clears the handler reservation and reports
  `ReservationTimedOut` immediately, allowing the behaviour to release shared
  capacity even while a peer keeps work ready on every poll. The focused
  regression places another ready handler event behind an expired reservation
  and proves expiry wins without discarding the queued work. The complete
  vendored relay crate tests (19 unit, seven integration, two doc tests) and
  warning-free all-target relay Clippy pass locally.

- [x] **M5-77 / gate — Recheck the corrected tree before closing Milestone 5.**
  On 2026-09-22 the corrected tree passed `cargo fmt --all -- --check`,
  `cargo test --locked --workspace --all-targets`, warning-free
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `scripts/docker-lab-safety-test.sh`. A fresh disposable local 2 GiB Btrfs
  image mounted with `user_subvol_rm_allowed` passed the complete
  `scripts/reflink-acceptance.sh` suite: all 12 anchor/reflink cases, all seven
  node interruption/recovery/headroom cases, five-node seed recovery, signed
  network commit and recovery, repeated multi-owner QUIC backups, and the real
  five-daemon namespace/NAT/DHT recovery path. The five-daemon scenario passed
  in 1,359.10 seconds; the disposable filesystem was unmounted and removed.
  All compilation and execution were local; no remote compilation server was
  used. Later source review reopened Milestone 5.

- [x] **M5-78 / P1 — Try a lower complete checkpoint candidate after a higher one fails.**
  `sync_checkpoint_head_once` selects the highest currently authorized advertised
  certificate (`crates/mb-node/src/network/p2p.rs:7191`) but clears catch-up and
  returns on missing generation quorum, unavailable link, or failed installation
  (`:7250`–`:7302`). A recovered peer may legitimately advertise a high certified
  head without intermediate certificate records, while another peer has a lower
  complete chain. Each pass reselects the same high candidate, so the lower head
  is never installed. Continue through other candidates in the same bounded pass
  or persist a bounded rejection cooldown; gate a persistent incomplete high
  head alongside a reachable complete lower head across restart.
  `151a29a` iterates other advertised candidates after a failed or resumed
  catch-up, clearing a failed target before retrying. `5076e8e` binds each
  intermediate quorum hash to the candidate's advertising source, so a
  different certified history cannot be chosen for that candidate. Its focused
  regression uses signed certificates and peer responses: a persistent higher
  head has no first-link evidence from its source, a lower head has a complete
  chain, and the lower head installs and remains durable across restart.

- [x] **M5-79 / P2 — Serve checkpoint generation lookups without scanning all history.**
  Each `GetCheckpointAtGeneration` loads every retained `guild-checkpoint`
  certificate into memory, decodes it, and verifies its signatures
  (`crates/mb-node/src/node.rs:9928`; `crates/mb-store/src/database.rs:346`).
  A 1,024-link catch-up repeats that full-history scan at every current peer for
  every link, so CPU work is quadratic in a long history; one authorized peer
  can also issue repeated absent-generation lookups. Add an atomically maintained
  generation-to-hash index or an equivalently bounded committed-history lookup.
  Gate long-history catch-up and repeated lookups with bounded reads and memory.
  `151a29a` atomically indexes committed generations, backfills old head
  ancestry on open, and makes each lookup read one indexed certificate.
  `f155406` adds 1,024 committed, signed generations, reopens the node, reads
  every generation, and repeats an absent lookup 128 times. The peer request
  handler calls this indexed node lookup directly. `40d83ec` sends signed peer
  requests for every generation of that committed history after restart and
  repeats the absent lookup 128 times. Each request loads one indexed hash and
  one certificate, so read work and retained certificate memory do not grow
  with history length.

- [x] **M5-80 / P1 — Use healthy replacement groups for restore and cold recovery.**
  M5-74's all-placement fallback covers backup packing, but ordinary packed
  snapshot restore still selects the first matching group from all retained
  groups, including retired ones (`crates/mb-node/src/network/p2p.rs:10897`).
  Cold guild recovery first requires every matching retained group to reconstruct
  (`:10218`–`:10267`) and then chooses the first group for each packed cache
  descriptor (`:10293`–`:10316`). During stale/replacement overlap, an old group
  with fewer than `k` reachable shards can fail restore or recovery despite a
  current certified replacement with a valid `k`. Prefer current active geometry,
  try every matching certified placement, and require only enough valid current
  coverage. Gate both restore and seed recovery with the stale group ordered
  first and unavailable.
  `8434b30` orders current active placements before stale or retired ones,
  retries matching certified placements during restore, and uses successful
  active-group coverage for cold recovery. `01cfd39` reconstructs from a
  current replacement over mocked shard responses while the old group is
  unavailable. `484e4ec` exercises the production coverage helper with those
  network shards. `f58d64e` runs full packed snapshot restore with old groups
  listed first and unavailable. `df014c1` uses the same fixture to run the
  production cold shard-recovery step with replay-verified replacement coding
  transcripts. Both paths fetch the current groups and recover the signed
  revision sector without requesting an old group.

- [x] **M5-81 / P2 — Bound legacy attestation lookup per packing pass.**
  For every retained legacy source, production packing calls
  `legacy_source_evidence` (`crates/mb-node/src/network/p2p.rs:12075`), which
  loads, decodes, and signature-verifies the entire durable attestation journal
  before checking the prior catalog's current-epoch evidence (`:12359`;
  `crates/mb-node/src/node.rs:3669`). With `N` attested legacy sources and a
  journal proportional to `N`, an unchanged backup does quadratic full-journal
  work despite metadata-only packed advancement. Index attestations by source,
  or load and index the journal once per packing pass; check valid prior-catalog
  evidence before scanning durable history. Gate a large unchanged mixed corpus
  with bounded row reads, signature checks, and peak memory.
  `b9d4e07` first checks current prior-catalog quorum and lazily builds one
  journal index for the remaining pass. `bb0d333` tests a 130-source mixed
  corpus and asserts index reuse. `ae9e6c3` streams journal rows into that
  single verified index, avoiding a second full journal allocation.
  `7287a4a` counts rows, signature checks, retained records, and peak encoded
  journal payload. `e959d92` runs the complete unchanged-catalog packing pass
  over 130 mixed sources: 128 use prior-catalog evidence, while the remaining
  two trigger one 138-row/138-signature journal scan. The retained index has
  138 records and its peak journal payload stays under 512 KiB; the streaming
  cursor holds only one additional row at a time.

- [x] **M5-82 / P1 — Report relay outbound worker overflow and release its circuit.**
  Guild relay configuration permits 32 circuits in the tested setting
  (`crates/mb-node/src/network/p2p.rs:697`), while a destination handler has
  only ten concurrent outbound STOP workers
  (`vendor/libp2p-relay/src/behaviour/handler.rs:55`). If the eleventh stream
  arrives while ten handshakes stall, `try_push` rejects it but the handler still
  inserts its request into `active_connect_requests` (`handler.rs:446`–`:463`).
  No worker can emit a result, leaving the source request and an `Accepting`
  circuit slot occupied until a connection closes. Send an explicit failure to
  the behaviour on overflow and avoid retaining the rejected request. Gate more
  than ten simultaneous stalled STOP handshakes on one destination connection,
  then prove the rejected circuit and shared capacity are released.
  `bed5b90` queues a resource-limit failure and skips active-request insertion
  when `try_push` overflows. `d1c94cc` removes the circuit as soon as the
  failure reaches the behaviour, even when source denial is stalled.
  `038107d` runs twelve CONNECT requests through in-memory relay swarms with
  ten STOP handshakes stalled on one destination connection. It observes both
  overflow failures and the circuit count returning to ten after each, proving
  shared capacity is released.

- [x] **M5-83 / P1 — Reject checkpoint authority epochs that move backward.**
  A nonfinal catch-up link may use any authority found anywhere in guild event
  history (`crates/mb-node/src/node.rs:6032`–`:6069`, `:6615`–`:6643`), while
  `validate_checkpoint_transition` checks its parent and state but never
  compares consecutive authority epochs (`:6678`–`:6825`). A certificate chain
  with A at generation 1, B after membership rotation at generation 2, revoked
  A at generation 3, and current B at generation 4 passes these local checks if
  signed certificates and peer responses are supplied. The third checkpoint
  cannot be an honestly signed pre-revocation successor of B, yet catch-up
  accepts it as historical. Require authority epochs to be nondecreasing along
  exact-parent links, including the legacy format transition. Gate this chain
  and valid forward A-to-B catch-up across restart.
  `b9d4e07` rejects explicit epoch decreases and format-5-to-legacy rollback.
  `7ee8397` uses the latest possible matching epoch for a format-4 predecessor;
  an ambiguous A -> B -> A member roster can no longer hide a rollback to B.
  The focused regression commits the legacy checkpoint, restarts, and rejects
  its B-epoch successor. The existing catch-up regression accepts a valid
  forward legacy-to-authority transition across restart. Ambiguous historical
  transitions are conservatively rejected when their epoch cannot be proven.

- [x] **M5-84 / gate — Recheck Milestone 5 after M5-78 through M5-83.**
  After correcting these source blockers, run a fresh source review, formatting,
  locked all-target workspace tests, warning-free locked all-target workspace
  Clippy, Docker lab safety, and the complete provisioned Btrfs/network
  acceptance script on a fresh disposable local filesystem. No remote
  compilation server may be used. Fresh source review of `9e3e194..e959d92`
  found no new blocker. On 2026-09-25, `cargo fmt --all -- --check`,
  `cargo test --locked --workspace --all-targets`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `scripts/docker-lab-safety-test.sh` passed locally. The complete
  `scripts/reflink-acceptance.sh` passed on a fresh disposable local Btrfs
  filesystem, including provisioned tests and the five-daemon network smoke
  test; its mount and image were cleaned up. No remote compilation server was
  used.

- [x] **M5-85 / P1 — Try each advertiser of the same checkpoint head.**
  `sync_checkpoint_head_once` de-duplicates candidates by head hash alone
  (`crates/mb-node/src/network/p2p.rs:7212`–`:7216`), but its intermediate
  generation quorum requires the selected advertising source to endorse each
  link (`:7288`–`:7295`, `:7377`–`:7385`). A seed-recovered peer can advertise a
  certified high head while having only that generation indexed
  (`crates/mb-store/src/database.rs:1075`–`:1122`). If it sorts before a peer
  advertising the same hash with the complete chain, its catch-up fails and
  the complete peer is skipped on every pass, including after restart. Try
  distinct `(head hash, advertising source)` candidates, including after a
  failed resumed attempt. Gate identical advertised heads under a majority
  quorum, with the first source missing an intermediate link and the second
  source complete. Corrected in `e9fadb2`; source review confirms the attempted
  key includes both hash and source for resumed and newly advertised heads.

- [x] **M5-86 / P1 — Validate legacy checkpoint epochs in historical order.**
  A format-4 checkpoint has no authority epoch. On a later format-5 transition,
  `latest_checkpoint_member_epoch` assigns it the latest matching roster epoch
  from the entire currently synced guild event history
  (`crates/mb-node/src/node.rs:6937`–`:6960`), then rejects a smaller explicit
  successor epoch (`:6794`–`:6808`). Peer exchange syncs events before
  checkpoints (`crates/mb-node/src/network/p2p.rs:7121`–`:7127`). Thus a valid
  format-4 checkpoint at unanimous epoch 1, format-5 successor at majority
  epoch 2, and later return to unanimous epoch 3 with a new format-5 head make
  a lagging peer reject that historical epoch-2 link forever: the old roster
  also matches epoch 3.
  Preserve rollback rejection while bounding legacy epoch inference to the
  checkpoint's historical transition. Gate late catch-up through this complete
  signed sequence and the existing invalid rollback sequence. Corrected in
  `75d0fd5`: an already accepted format-4 epoch is witnessed atomically with
  its checkpoint, while an unwitnessed historical link is bounded by its
  explicit successor epoch. Source review found no remaining blocker here.

- [x] **M5-87 / P1 — Let current replacement coverage satisfy cold recovery without a local role.**
  `variable_recovery_plans` includes a group's covered sectors only when the
  recovering node owns an information or parity shard in that group
  (`crates/mb-node/src/network/p2p.rs:10255`–`:10286`). During the normal
  overlap before a separate `RetireCodingGroup` event, a node can hold parity
  in the stale group but have no role in a healthy current replacement. The
  replacement is omitted from its plans, so recovery requires the unavailable
  stale group and aborts before installing the recovered checkpoint
  (`:10464`–`:10480`, `:8876`–`:8880`). Determine live-sector coverage from
  current certified groups independently of the node's local shard targets;
  recover only shards it still needs. Gate cold recovery in a six-member guild
  where stale-group parity belongs to the recovering node, replacement parity
  belongs elsewhere, the old group is unavailable, and the current replacement
  has a valid `k`. Commit `1e8ee2b` adds coverage-only plans and a parity-only
  regression, but source review found that its success does not always prove
  a live `k`: `recover_variable_group_plan` probes one live information shard
  (`crates/mb-node/src/network/p2p.rs:10530`–`:10559`), while
  `reconstruct_variable_shard_from_peers` returns immediately when that shard's
  holder answers (`:10889`–`:10900`). The coverage loop then marks every sector
  in the group covered (`:10492`). If a group has multiple live information
  sectors and only the probed holder is reachable, cold recovery can skip the
  unavailable stale group and accept a checkpoint despite insufficient shards
  to reconstruct the other sectors. The new regression uses one live sector
  and virtual-zero roles, so it does not cover this case. Require verified
  reachability of `k` distinct shards (counting authenticated virtual zeros)
  before coverage-only success. Add a negative multi-live-sector regression
  with fewer than `k` reachable shards and a positive one with any valid `k`.
  Corrected in `dd5c7e8`: coverage-only recovery now skips the direct-shard
  shortcut and requires `k` distinct commitment-verified shards, counting
  authenticated virtual-zero roles. The new two-live-sector regression rejects
  one reachable shard and accepts two; the six-member parity-only cold recovery
  regression still passes locally.

- [x] **M5-88 / gate — Recheck Milestone 5 after M5-85 through M5-87.**
  After correcting these source blockers, run fresh source review, formatting,
  locked all-target workspace tests, warning-free locked all-target workspace
  Clippy, Docker lab safety, and the complete provisioned Btrfs/network
  acceptance script on a fresh disposable local filesystem. Build and run
  locally; do not use a remote compilation server. Fresh source review of the
  final correction tree through `dd5c7e8` found no further blocker. On
  2026-09-25, `cargo fmt --all -- --check`,
  `cargo test --locked --workspace --all-targets`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `scripts/docker-lab-safety-test.sh` passed locally. The complete
  `scripts/reflink-acceptance.sh` passed on a fresh disposable 8 GiB local
  Btrfs image, including its provisioned filesystem tests, repeated multi-owner
  QUIC backups, and five-daemon seed/DHT recovery network smoke test. The
  mount, loop device, image, and smoke-test namespaces were removed. No remote
  compilation server was used.

- [x] **M5-89 / P1 — Bind cold replacement coverage to the checkpoint's authenticated sector.**
  `variable_recovery_plans` collects checkpoint sectors as IDs and its new
  coverage-only pass treats a current group's information role as a match on
  ID alone (`crates/mb-node/src/network/p2p.rs:10227`–`:10319`). A separately
  certified `AddCodingGroup` may reuse a legacy sector ID with different
  committed bytes or a different information owner; guild event validation
  checks the group's placement and transcript, but does not bind that new
  group to an older checkpoint (`crates/mb-core/src/guild.rs:490`–`:510`,
  `crates/mb-node/src/node.rs:2844`–`:2860`). A format-5 checkpoint can remain
  valid through a stale group with the correct owner and root, while a current
  group without a recovering parity holder's role has the same ID and different
  authenticated content. The current group can provide `k` shards of the wrong
  bytes, be marked as covering the checkpoint sector, and make cold recovery
  skip the unavailable stale group. The historical checkpoint validator still
  accepts the stale certified placement
  (`crates/mb-node/src/node.rs:6121`–`:6165`), so the
  checkpoint can be installed without recoverable protection for that sector.
  Match exact checkpoint authentication before counting coverage: owner,
  logical length, and transcript information root for legacy references;
  catalog commitment and flat root for packed sectors. Gate a same-ID,
  different-root current group against an unavailable correct stale group.
  The correction checks each claimed information role against the checkpoint's
  owner and length or packed commitment, then checks the transcript root.
  Legacy transcripts without roots reconstruct and compare sector bytes.
  Focused local regressions reject a same-ID wrong-root current group with an
  unavailable correct stale group, and packed commitment/root mismatches.

- [x] **M5-90 / P2 — Stop cold recovery work after sufficient current coverage.**
  The coverage-only second pass adds every current group overlapping a required
  sector, even when one healthy replacement covers it
  (`crates/mb-node/src/network/p2p.rs:10287`–`:10319`).
  `recover_variable_plan_coverage` awaits all current plans before checking
  whether the required sectors are covered (`:10467`–`:10513`), and
  `collect_bounded_recovery_requests` drains the entire iterator (`:9084`–`:9100`).
  Dynamic guild state accepts multiple distinct overlapping coding groups with
  no group-count or overlap bound (`crates/mb-core/src/guild.rs:263`–`:280`,
  `:490`–`:510`). One healthy current replacement plus stalled or unavailable
  redundant groups therefore forces unnecessary `k`-shard fetches and waits;
  repeated certified groups make the transfer and delay grow with history.
  Keep concurrency bounded and stop or cancel redundant probes once exact
  required coverage succeeds, while still trying another placement when the
  first fails. Gate healthy-first with stalled redundant groups and failed-first
  fallback, including a bound on issued shard requests.
  Current groups now run in bounded batches with disjoint needed sectors;
  successful coverage stops redundant probes and failures allow alternatives.
  Focused local tests cover stalled redundant groups, failed-first fallback,
  the eight-group in-flight bound, and network recovery that requests shards
  only from its healthy replacement.

- [x] **M5-91 / gate — Recheck Milestone 5 after M5-89 and M5-90.**
  After correcting both source blockers, run fresh source review, formatting,
  locked all-target workspace tests, warning-free locked all-target workspace
  Clippy, Docker lab safety, and the complete provisioned Btrfs/network
  acceptance script on a fresh disposable local filesystem. Build and run
  locally; do not use a remote compilation server. M5-88 remains historical
  evidence for its exact source tree.
  Fresh source review found no remaining blocker. On source commit `09e9379`,
  `cargo fmt --all -- --check`, `cargo test --locked --workspace --all-targets`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `scripts/docker-lab-safety-test.sh` passed locally. The complete
  `scripts/reflink-acceptance.sh` passed on a fresh disposable 8 GiB local
  Btrfs image, including its provisioned filesystem tests, repeated multi-owner
  QUIC backups, and five-daemon seed/DHT recovery smoke test. The mount, loop
  device, image, and smoke-test namespaces were removed. No remote compilation
  server was used.

- [x] **M5-92 / P1 — Bind claimed legacy information roots to committed bytes.**
  Cold recovery accepts a format-2 transcript's claimed information root as
  checkpoint proof without reconstructing its shard
  (`crates/mb-node/src/network/p2p.rs:10306`–`:10336`). A signed plan can
  claim the expected legacy flat root while the group's Merkle commitment and
  actual information bytes differ: `CodingAttemptPlan::validate` does not bind
  them, and `replay_coding_transcript` checks signed sampled openings and the
  sampled codeword, not the claimed full-content root
  (`crates/mb-core/src/attempt.rs:232`–`:258`, `:590`–`:712`). Honest
  `encode_coding_attempt` checks its inputs, but replay of externally supplied
  certified evidence does not enforce that check. Such a group can receive
  credit for live `k` of wrong bytes and suppress a correct stale fallback.
  Make every accepted claimed root a verified binding to the committed full
  information shard, including checkpoint-signing and cold-recovery paths.
  Gate a replay-valid, false-root transcript against wrong committed bytes and
  an unavailable correct stale placement. Cold recovery now reconstructs and
  checks legacy flat-root bytes even when the transcript claims the expected
  root; a focused local regression rejects a replay-valid false-root group.
  Checkpoint-signing coverage still needs the same binding. Commit `308b156`
  requires a revision-signed Merkle commitment for a new legacy checkpoint,
  but `verified_variable_sector_coverage` accepts a group when that commitment
  matches the role and a format-2 plan merely *claims* the revision's flat root
  (`crates/mb-node/src/node.rs:6408`–`:6431`). Neither
  `GuildCheckpoint::validate` nor `CodingAttemptPlan::validate` proves that
  the revision's flat root and Merkle commitment describe the same bytes
  (`crates/mb-core/src/model.rs:790`–`:797`;
  `crates/mb-core/src/attempt.rs:249`–`:258`). A signed revision with flat
  root A and commitment for B, plus a replay-valid group for B claiming A,
  can therefore still be signed as protected. A rootless format-1 group for B
  also passes the commitment-matching branch. Bind the roots through full
  authenticated bytes or an equivalent verifiable proof. Add checkpoint
  signing regressions with this inconsistent signed root/commitment pair for
  both transcript formats. Commit `c7cc6fd` adds that proof to version-three
  legacy coding manifests and requires it before signing new legacy variable
  or old flat-root packed coverage. The coordinator computes both roots from
  complete encrypted information bytes; replay independently recomputes them.
  Focused local regressions reject replay-valid format-1/2 false claims, a
  forged version-three manifest, and inconsistent signed revision roots while
  accepting a correct version-three group. Compact production packed groups
  retain format two because their descriptor root equals the Merkle root.

- [x] **M5-93 / P1 — Require live `k` when current local targets are READY.**
  `recover_variable_group_plan` proves a live quorum for coverage-only plans,
  but sends current plans with local targets to `recover_variable_plan`
  (`crates/mb-node/src/network/p2p.rs:10649`–`:10705`). That function skips
  network reconstruction for each target already READY and can activate the
  transcript without fetching any peer shard (`:10707`–`:10755`). A retry
  retaining only its local current parity shard can mark replacement coverage
  complete with fewer than `k` live shards and skip a stale fallback. Prove a
  live decoding quorum before crediting the current group even when every
  local target is READY. Gate interrupted recovery with one READY local shard,
  fewer than `k` live shards, and an available correct fallback. Recovery now
  proves a live quorum for every group before crediting it and reuses the
  verified bytes to stage a local target. A focused local regression rejects
  a READY local parity shard alone and succeeds when another valid remote
  shard becomes reachable; fallback scheduling remains covered by the existing
  current/fallback recovery tests.

- [x] **M5-94 / P1 — Continue ordinary restore after a wrong-root placement.**
  Legacy restore selects certified variable placements by sector ID, prefers
  a current placement, and takes the first reconstruction that matches that
  group's commitment (`crates/mb-node/src/network/p2p.rs:11345`–`:11399`,
  `:13074`–`:13163`). It checks the signed revision root only after placement
  fallback has ended. A reachable same-ID current group with different bytes
  therefore aborts restore even when a correct stale group is available.
  Match authenticated owner, length, and root before accepting a placement, or
  treat a revision-root mismatch as a per-placement failure and continue.
  Gate wrong-root current placement followed by a recoverable correct stale
  placement. The restore path now filters owner and logical length and checks
  each reconstructed candidate against the signed revision root before
  accepting it. A focused local network regression passed with reachable
  wrong-root bytes followed by a correct placement.

- [x] **M5-95 / P2 — Credit valid sectors within mixed recovery groups.**
  `variable_recovery_plans` collects all matching checkpoint IDs into a
  group's `covered` set (`crates/mb-node/src/network/p2p.rs:10339`–`:10430`).
  Coverage scheduling can select that group for one still-needed sector, but
  `recovery_plan_missing_roots` rejects it when any other planned sector has
  a mismatched checkpoint root (`:10306`–`:10336`, `:10568`–`:10620`). Thus a
  live group with valid A and old/wrong-root B cannot cover A after another
  group already covered B; recovery can fail despite both sectors being
  recoverable. Authenticate and credit only the still-needed matching sectors
  without losing valid coverage from the group. Gate mixed correct/wrong-root
  groups with independent coverage for the conflicting sector. Recovery now
  returns only sectors authenticated against the checkpoint and skips unrelated
  mismatched roles. Focused local regressions cover a live mixed group that
  credits valid A despite conflicting B and then credits B from another group.

- [x] **M5-96 / P1 — Authenticate retained-revision coverage and audit.**
  For a revision retained from the preceding checkpoint, checkpoint validation
  passes `allow_legacy_root` to variable coverage
  (`crates/mb-node/src/node.rs:6187`–`:6249`). That accepts a rootless format-1
  transcript matching owner, sector ID, and length without proving its bytes
  match the signed revision root (`:6348`–`:6395`). A newly certified
  wrong-byte format-1 group is still accepted by attempt-authority replay
  (`crates/mb-core/src/guild.rs:584`–`:618`) and can replace the correct
  placement while the next checkpoint signs the retained revision as protected.
  The checkpoint audit also matches legacy groups by owner, ID, and length alone
  (`:9716`–`:9744`;
  `crates/mb-node/src/network/p2p.rs:9518`–`:9540`), and can report the wrong
  group healthy. Require exact signed-root protection for replacement groups
  even when a revision is retained, and make audit use the same authenticated
  coverage. Gate a retained revision with a wrong-byte format-1 replacement
  through checkpoint signing and audit. Commit `308b156` rejects that rootless
  successor and makes audit reconstruct and check the checkpoint bytes; its
  focused regression passed locally before this source-only review. The
  checkpoint signer still accepts a retained signed revision whose flat root
  and signed Merkle commitment are inconsistent, through the M5-92 path above.
  Gate that retained-revision case as well before closing this item. Commit
  `c7cc6fd` requires a replay-verified full-byte root binding for every new
  legacy checkpoint, including retained revisions. A focused local regression
  rejects both a format-2 false-root claim and a rootless format-1 group for
  an inconsistent retained revision; audit continues to check reconstructed
  bytes against the committed checkpoint.

- [x] **M5-97 / gate — Close Milestone 5 after the root-binding, migration, length, and alignment corrections.**
  After correcting the source blockers, run fresh source review, formatting,
  locked all-target workspace tests, warning-free locked all-target workspace
  Clippy, Docker lab safety, and the complete provisioned Btrfs/network
  acceptance script on a fresh disposable local filesystem. Build and run
  locally; do not use a remote compilation server. M5-91 remains historical
  evidence for its exact source tree. The correction series through `c7033fa`
  resolves M5-92 through M5-102. Final source review covers legacy full-byte
  root/length binding in signing, recovery and audit, historical evidence and
  durable-job migration, both transport encodings, and aligned resumable
  holder writes. Focused positive/negative regressions and the full gate pass.
  Commits `8433c86` and `c7033fa` implement M5-101 and M5-102. The final
  source tree `c7033fa` passed formatting, locked all-target workspace tests,
  warning-free locked all-target workspace Clippy, and Docker lab safety
  locally on 2026-09-26. Node tests: 255 passed, 10 provisioned tests ignored;
  core: 48 passed; store: 50 passed, 14 provisioned tests ignored. These counts
  exclude the other passing workspace targets. The complete
  `MUTUALBACKUP_REFLINK_TEST_ROOT=... bash scripts/reflink-acceptance.sh` also
  passed on a fresh disposable local 8 GiB Btrfs filesystem at `4170dce`
  (documentation-only changes from `c7033fa`). It includes capture/resumption,
  descriptor and storage-headroom checks, five-active-node seed recovery,
  signed network commit/recovery, repeated multi-owner QUIC backups, and real
  five-daemon seed/DHT recovery with direct, DCUtR, and forced relay bulk
  transfers. All 23 test invocations passed; the final process test passed in
  1348.52 seconds. Cleanup and
  subsequent checks confirm the mount, loop/image, namespaces, and test
  daemons are gone. No remote compilation server was used. Milestone 5 is
  closed; Milestone 6 is next.

- [x] **M5-98 / P1 — Give upgraded legacy attempts a distinct durable identity.**
  `queue_variable_coding_lanes` now emits format-3 legacy plans but derives
  `attempt_id` from the same checkpoint, geometry, and information roots as
  the former format-2 plan, without including the plan version
  (`crates/mb-node/src/network/p2p.rs:12358`–`:12380`).
  `same_coding_lane_attempt` requires matching format versions, and
  `enqueue_coding_launch` rejects collisions with durable launch, retry, or
  activation records (`crates/mb-node/src/node.rs:276`–`:284`,
  `:3941`–`:3973`). Restarting interrupted legacy coding after upgrading
  therefore repeatedly rejects the stronger plan instead of scheduling it.
  Separate upgraded attempt identities while preserving historical retry and
  decoding behavior. Gate an installed format-2 launch, retry, and activation
  record against scheduling the same lane with format 3 after reopening the
  node; the stronger attempt must make progress without deleting old evidence.
  Format-3 plans now use a separate deterministic hash context while compact
  format-2 IDs remain byte-exact. A focused local restart regression installs
  each old durable job kind, queues and claims the stronger attempt, and checks
  that the original record is unchanged.

- [x] **M5-99 / P1 — Permit stronger evidence for an already certified legacy group.**
  Even with a fresh attempt ID, `encode_coding_attempt` always emits a
  format-2 group with the same roles and commitments
  (`crates/mb-core/src/attempt.rs:715`–`:723`). The group's ID excludes the
  plan version and root-binding evidence (`crates/mb-core/src/model.rs:285`–
  `:292`), so recoding identical bytes and placements reproduces its old ID.
  `validate_coding_transcript_storage_conflicts` rejects any different
  transcript stored under that group ID (`crates/mb-node/src/node.rs:2861`–
  `:2885`), and `commit_verified_coding_group` returns immediately when the
  descriptor already exists (`crates/mb-node/src/network/p2p.rs:6942`–`:6947`).
  New legacy checkpoint coverage now requires format-3 evidence, so a
  certified old group cannot acquire the proof required to protect a successor.
  Define an authenticated evidence upgrade or a distinct group identity for
  stronger proofs, keeping old checkpoints recoverable and conflicting
  evidence rejected. Gate a durable certified format-2 group, then a correct
  full-byte proof for the same bytes/placement through activation, event
  persistence, restart, successor checkpoint signing, and historical recovery.
  New full-byte encoding emits group format 3, whose version participates in
  its ID; compact plans remain restricted to group format 2. Historical full
  proofs for format-2 groups still replay. READY information with matching
  authenticated guild/commitment is reused without rewriting its old attempt
  record. The focused local migration regression certifies both layouts,
  reopens storage, reads both transcripts and inputs, validates historical
  compact coverage, and signs a new checkpoint with the stronger proof.

- [x] **M5-100 / P2 — Bound full-byte manifests by encoded peer-frame size.**
  Format-3 validation permits `k * shard_size` up to 512 KiB
  (`crates/mb-core/src/attempt.rs:250`–`:253`), claiming this fits a 600 KiB
  frame. The payload is ordinary nested `Vec<u8>` (`:293`), serialized by
  Serde as integer sequences rather than CBOR byte strings. Values at least
  24 require two CBOR bytes. A valid `4+2` profile with 128 KiB information
  shards can therefore produce a manifest exceeding 600 KiB before envelope
  overhead; parity staging also carries a complete parity object
  (`crates/mb-node/src/network/wire.rs:143`–`:147`). The QUIC codec enforces
  that frame limit (`crates/mb-node/src/network/p2p.rs:712`–`:718`;
  `crates/mb-node/src/network.rs:75`). Such accepted plans cannot complete
  remote staging or transcript exchange. Use a version-compatible compact
  byte representation and budget every containing request/response, or split
  the authenticated witness into bounded messages. Gate worst-case payloads
  at the largest accepted geometry through actual encoded staging, challenge,
  transcript, and event-tail envelopes on both peer transports; keep legacy
  manifest serialization compatible.
  New manifest format 3 uses CBOR byte strings; formats 1–2 retain their
  original layouts and remain readable. New attempt validation budgets
  worst-case signed control envelopes, proofs, and certificates against both
  encodings before staging. Parity range size uses the actual remaining frame
  budget; full-byte staging uses these ranges. Event-tail responses return
  the largest fitting prefix. The focused local transport regression uses
  512 KiB of worst-case ciphertext and maximum-length domain claims, checks
  staging/challenge/transcript/certification envelopes with the CBOR codec and
  Postcard, verifies historical layout compatibility, and rejects a dense
  raw-size-valid plan whose control evidence cannot fit its containing frames.

- [x] **M5-101 / P2 — Enforce the fixed legacy ciphertext sector length.**
  `verified_variable_sector_coverage` matches owner, sector ID, logical length,
  and the replay-verified flat root without requiring the information
  commitment's byte length to equal `V1_SECTOR_SIZE`
  (`crates/mb-node/src/node.rs:6401`–`:6442`). Legacy recovery/audit
  authentication likewise checks roots but accepts any full-shard length
  (`crates/mb-node/src/network/p2p.rs:10346`–`:10383`). A version-three user
  revision without a separately signed Merkle commitment can therefore receive
  new checkpoint protection from a correct proof for a short shard, while
  ordinary restore and `crypt_sector` require 64 KiB
  (`crates/mb-node/src/network/p2p.rs:11520`,
  `crates/mb-core/src/content.rs:100`–`:102`). The migration/lifecycle fixtures
  currently use 64-byte shards and demonstrate this accepted checkpoint shape.
  Require the implicit V1 ciphertext length for legacy references in checkpoint
  coverage, cold recovery, and audit; keep packed variable profiles governed by
  their explicit descriptor commitments. Gate a fully root-bound short shard
  against checkpoint signing and recovery/audit authentication, and use full
  V1 ciphertext sectors for positive legacy checkpoint fixtures.
  Checkpoint coverage, audit candidate selection, and shared recovery/audit
  authentication now require complete V1 ciphertext sectors for legacy
  references. Packed descriptors retain their explicit length. Focused local
  regressions pass for fully root-bound short-shard rejection, complete-sector
  migration and successor signing, staging/activation, and both authentication
  modes. The complete final M5-97 gate remains pending.

- [x] **M5-102 / P1 — Align adaptive parity uploads to Merkle leaves.**
  `coding_parity_range_bytes` returns the remaining encoded-frame budget,
  divided by two for CBOR and capped at 256 KiB, without rounding it down to
  `MERKLE_LEAF_SIZE` (`crates/mb-node/src/network/wire.rs:625`–`:646`).
  Both full-byte staging and delegated encoding use that number directly as
  the next upload length (`crates/mb-node/src/network/p2p.rs:2474`–`:2484`,
  `:6702`–`:6730`). For a frame-limited witness, the available budget need not
  be a multiple of 16. The holder rejects such a range before writing because
  both its offset and byte count must be leaf-aligned
  (`crates/mb-store/src/database.rs:1502`–`:1514`, reached through
  `crates/mb-node/src/node.rs:4677` and `crates/mb-node/src/volume.rs:881`).
  Thus an accepted, transportable plan can repeatedly fail staging; the current
  frame regression only serializes uploads and does not exercise this storage
  precondition (`crates/mb-node/src/network/wire.rs:1005`, `:1024`). Round the
  chosen size down to a complete leaf before checking the minimum. Gate a
  frame-limited full-byte manifest through actual holder writes, interrupted
  upload/reservation resume, and finalization, with varying envelope/domain
  sizes; every chosen chunk and resumed offset must remain aligned while both
  encoded transports stay within their limits. This finding is source-only;
  no builds, tests, daemons, or runtime probes were run for this review.
  The shared range budget now rounds down to complete Merkle leaves. The
  focused local frame regression passes with four envelope/domain sizes,
  including a raw unaligned budget: it writes every chunk through the holder's
  SQLCipher range API, reopens after the first chunk, resumes the reservation,
  finalizes the committed parity row, and verifies its opening. Every upload
  also fits both serialized transport limits. The final M5-97 gate remains open.

- [x] **M5-103 / P1 — Let replacement coding work progress past a blocked durable retry.**
  Distinct format-3 attempt IDs allow enqueue alongside the old format-2
  retry, but do not make the production worker dispatch it. The first
  incomplete retry is claimed repeatedly, and deferral only records an error
  while leaving it incomplete (`crates/mb-node/src/node.rs:4944`–`:4960`,
  `:5015`–`:5040`). `run_delegated_coding_jobs` unconditionally continues
  after retry failure, before launch dispatch or activation
  (`crates/mb-node/src/network/p2p.rs:6131`–`:6173`). A concrete same-epoch
  restart can leave a prepared retry past its ten-minute deadline: retry
  execution reuses that exact signed plan forever (`:6352`–`:6353`), while
  delegated enqueue rejects expired plans (`crates/mb-node/src/node.rs:4110`,
  `:5382`; `crates/mb-core/src/guild.rs:575`). Even with all peers back online,
  the queued stronger legacy proof and every unrelated launch/activation stay
  unreachable. A retry without a prepared plan also fails indefinitely in a
  supported three-member guild: excluding both old coordinators leaves only
  one fresh candidate, but retry requires two (`network/p2p.rs:6381`–`:6400`).
  Membership-epoch changes retire these retries, but an ordinary restart or
  proof-format upgrade does not change the epoch. The new migration regression
  directly claims the replacement launch (`node.rs:13922`–`:13964`), bypassing
  this worker schedule.
  Handle expired or superseded retries with fresh identities and valid
  authority while preserving signed history and safe staged-data cleanup.
  Give deferred retries bounded scheduling turns so launches and activations
  can progress; keep insufficient fresh coordinators an explicit blocked
  state rather than monopolizing the worker. Gate a same-epoch reopen with an
  expired prepared format-2 retry, all peers reachable, and a queued format-3
  replacement through the actual background worker to verified activation
  and checkpoint coverage, preserving old evidence. Also cover a three-member
  retry lacking two fresh coordinators alongside unrelated eligible launch
  and activation work, and repeated reopen without resurrecting expired work.
  This finding is source-only; no builds or tests were run.
  The correction gives every worker queue a turn and rotates retry claims.
  Before cleanup it durably fences late results; late failure reports are
  archived without resurrecting work. Expired plans and the original signed
  failure remain intact. Successful cleanup records the expired parent and
  renews with a fresh attempt ID, fresh coordinator pair, current authority,
  and format 3 when legacy flat roots require complete-byte evidence. A queued
  stronger replacement supersedes compact work; same-format replanning reuses
  an already prepared retry instead of creating conflicting group evidence.
  Stale membership retries also clean their prepared uploads before completion.
  Four real QUIC worker regressions pass for stronger replacement after reopen,
  renewal without replacement, three-member blocked retry fairness, and stale
  prepared-upload cleanup. They exercise partial durable parity writes,
  verification, activation, checkpoint signing, reservation removal, and two
  further reopens. The focused `retry` run passed all 12 selected tests locally.
  Node regressions cover rotating claims, retirement fences, idempotent late
  failure archival, and preserving already submitted verifier evidence.
  The complete final M5-104 gate remains pending. All validation is local.
  Final review also found that completed delegated jobs were considered stale
  before their terminal state was checked. A lower-ID completed job could
  repeatedly hide an unfinished old-epoch upload. Claims now skip completed
  work before authority replay. The legacy restart regression covers both
  jobs across membership change and reopen, then selects and discards the
  unfinished upload without resurrecting either completed record. Its focused
  run passes. The initial M5-104 acceptance run passed 21 checks on `b9aadcc`
  before it was deliberately stopped for this correction; its disposable
  filesystem, image, loop device, and namespaces were removed. A new complete
  gate is required on the final corrected source.

- [x] **M5-104 / gate — Recheck Milestone 5 after durable retry scheduling is corrected.**
  Completed on 2026-09-26 against exact committed source
  `f8e47d34d62a073db6953260571441525dc5e2ac`, with a clean worktree throughout
  the final workspace and provisioned gates. `cargo clippy --locked --workspace
  --all-targets -- -D warnings` passed in 34.17 seconds. `cargo test --locked
  --workspace --all-targets` passed every suite: 48 core, 270 node (10 ignored)
  and 50 store (14 ignored), plus all CLI/application and vendored workspace
  targets. The node suite finished in 472.87 seconds and includes all recent
  launch-expiry, ownership, staging, fairness, membership and relay/DCUtR
  regressions. `cargo fmt --all -- --check` and
  `bash scripts/docker-lab-safety-test.sh` passed.

  All 23 invocations in `scripts/reflink-acceptance.sh` passed on a fresh local
  8 GiB Btrfs image. Repeated multi-owner QUIC finished in 1391.14 seconds;
  `five_daemons_recover_latest_snapshot_from_seed_and_dht` finished in
  3583.56 seconds, covering owner/storage-only seed recovery and direct,
  DCUtR and forced-relay bulk transfers. The runner exited zero and reported
  cleanup `result=0`. Independent checks confirmed that
  `/tmp/mutualbackup-m5-104.wFKFzL` (including mount/image) was absent,
  `/dev/loop0` was detached, all four `b5340b9` namespaces and their veth and
  firewall/NAT rules were gone, and no test daemon/harness processes remained.
  Workspace evidence is in `/tmp/mutualbackup-m5-104-owner-final-2-*.log`;
  provisioned evidence is in
  `/tmp/mutualbackup-m5-104-owner-final-provisioned.log`. No remote compilation
  server was used. Milestone 5 was closed at that point. The later M5-111
  through M5-113 source review reopens it; M5-114 is the new closure gate.

  Earlier review and gate history:

  Earlier source-only review on 2026-09-26 covers `16c28a5..77c2090` and the
  existing uncommitted relay/DCUtR fixture change. No new source blocker was
  found in expired acknowledged-launch selection, acknowledgement-preserving
  deferral/replanning, retirement before cleanup, accepted-result priority,
  reachable replacement selection, or atomic successor/staging-intent reuse.
  The added regressions cover coordinator shutdown, expiry and same-epoch
  reopen with explicit majority quorum, accepted evidence across expiry, and
  ownership preservation when the same attempt is proposed again.
  The relay fixture explicitly dials its circuit before starting the first
  event loop and disables background DHT maintenance for its three initial
  nodes; hole-punch, relay retirement, application-byte and fallback assertions
  remain present. This source edit is still uncommitted. Finalize that change
  before recording the complete gate against an exact committed source tree.
  This review ran no builds, tests, daemons, or runtime probes. Milestone 5
  remains open for this gate; previous validation records do not establish
  completion of the final tree.

  The subsequent local workspace gate on `77c2090` passed strict Clippy and
  48 core tests, but finished with 269 node passes and one relay/DCUtR fixture
  failure: discovery established a plain direct session before the intended
  relay circuit, so the test never exercised hole punching. The fixture now
  disables background DHT maintenance for its initial three nodes, retains the
  actual circuit address, and starts a tracked policy dial before the first
  event loop runs. A raw swarm-dial intermediate failed its first request and
  was replaced by that existing policy-dial path. Production transport is
  unchanged; all hole-punch, relay-retirement, application-byte and fallback
  assertions remain. The corrected targeted regression passes in 20.30 seconds
  (`cargo test --locked --workspace --all-targets
  relay_circuit_supports_application_requests_and_dcutr_upgrade -- --nocapture`).
  The complete workspace and fresh provisioned gate remain required.

  Correct M5-110 after the M5-108/M5-109 follow-up, then review the complete
  M5-103 follow-up and its production-worker restart/replanning regressions.
  Then run formatting, locked all-target workspace tests, strict locked
  all-target workspace Clippy, Docker lab safety, and the complete fresh
  disposable local Btrfs/network acceptance script. Record exact source
  commits and outcomes, and remove disposable resources. M5-97 remains a
  passed historical gate; it does not cover the missing retry schedule.
  All compilation and execution must remain local, with no remote server.
  The complete local gate on source `1f3141e` subsequently finished: locked
  all-target workspace tests passed (48 core, 264 node with 10 ignored, and 50
  store with 14 ignored), strict locked all-target Clippy passed, formatting
  passed, and Docker lab safety passed. All 23 fresh Btrfs/network acceptance
  invocations passed; repeated multi-owner QUIC took 557.28 seconds and the
  final five-daemon recovery/transport scenario took 1347.19 seconds. Cleanup
  reported success; the image/directory, loop device, and namespaces were
  independently confirmed removed. This is historical evidence for `1f3141e`,
  preceding M5-108/M5-109. Run a new complete gate on their final source.

- [x] **M5-105 / P1 — Coalesce only with live retry work or completed protection.**
  The new format-3 scan in `enqueue_coding_launch`
  (`crates/mb-node/src/node.rs:3947`–`:3956`) returns the first same-lane
  `retry_plan` using historical authority validation only. It does not check
  expiry, retirement, a subsequent failure, or whether a completed retry has
  any remaining launch/activation/coverage. Successful delegation marks the
  parent retry complete immediately (`network/p2p.rs:6169`–`:6174`), preserving
  that signed child forever. A concrete chain is A -> B (format 3), then B
  fails and creates its own retry job. The completed A record still names B.
  If B's prepared child expires and is retired/renewed, scanning A can still
  return failed B instead of the live successor. If B cannot find two fresh
  coordinators, a fresh same-lane launch is suppressed by B although it has
  neither activation evidence nor runnable work. `claim_coding_retry` skips
  completed A (`node.rs:5009`), so it cannot repair that stale pointer.
  Historical authority validation explicitly omits current time/liveness
  (`node.rs:5613`–`:5620`). Retain immutable evidence, but resolve the live
  successor or verified retained coverage before suppressing a launch. Do not
  treat a failed, retired, expired, or abandoned historical child as work.
  Gate multi-generation retries with adverse record ordering, expired/retired
  descendants, insufficient fresh roles, and repeated reopen. Exercise actual
  background dispatch through activation/checkpoint coverage, and preserve
  all original signed records. This finding is source-only; no tests were run.
  Coalescing now prefers replay-verified activation evidence and current
  retained protection, then a valid live retry child. Failed, retired, expired,
  and terminal children are skipped while signed history stays intact. A
  same-format replacement supersedes the blocked retry after safe cleanup;
  preparation rechecks supersession before signing another child. Replanning
  and enqueue enforce fresh roles relative to the latest failed/expired/retired
  attempt, preserving the fresh-coordinator invariant. A node regression
  covers adverse record ordering, multi-generation failure, expired/retired
  plans, live successors, rejected role reuse, verified activation, and reopen.
  A real QUIC regression drives a failed format-3 child with a retired prepared
  descendant through production replanning, cleanup, activation, checkpoint
  signing, and two further reopens, preserving original signed evidence.
  The focused `retry` run passed all 16 selected tests locally. M5-104 remains
  pending on the final committed source.

- [x] **M5-106 / P1 — Resolve the selected attempt before staging coding inputs.**
  `queue_variable_coding_lanes` stages information under its newly signed
  deterministic plan (`crates/mb-node/src/network/p2p.rs:12508`–`:12529`), then
  calls `enqueue_coding_launch` and ignores the returned plan. The new
  coalescing branch can instead return an existing random-ID format-3 retry
  without creating a launch for the staged deterministic ID. This is reachable
  while a delegated retry is running: its parent is already complete and
  `coding_checkpoint_has_pending` ignores completed retry records
  (`node.rs:4057`–`:4066`), allowing the lifecycle replacement planner to queue
  the still-uncovered lane (`network/p2p.rs:7681`–`:7686`, `:7787`). Legacy
  information available through `sector_for_guild` is still uploaded by the
  staging helper; only an existing READY variable object skips reservation
  (`node.rs:4551`–`:4569`, `:4656`–`:4670`). Upload completion leaves a durable
  STAGED object and `volume-attempt-receipt` for the unused ID
  (`volume.rs:936`–`:961`). Activation and abort act on the selected plan's ID,
  so they do not consume or discard these objects. The new regression invokes
  enqueue directly after coverage (`network/p2p.rs:22584`–`:22585`), bypassing
  production staging; zero reservations also cannot detect finalized STAGED
  receipts. Select/reuse the durable attempt before allocating inputs, or
  durably arrange cleanup of every unused staged attempt, including failure
  and restart windows. Gate the real queue path while a format-3 retry is
  pending, with locally available legacy bytes and no READY variable copy;
  verify staged receipts/objects and used capacity as well as reservations
  after activation, failures, and repeated reopen. Preserve signed history.
  This finding is source-only; no tests were run.
  Production queuing now selects the durable attempt before any input upload.
  A new launch and its input-staging intent are written atomically; a coalesced
  retry gets no unused upload. The worker resumes staging under that launch's
  signed ID and clears its intent only after successful placement, before
  delegation. Failures retain the resumable launch, partial upload, and error;
  stale-authority cleanup removes its intent after discarding staged data.
  Staging intent uses a separate record, preserving the positional CBOR launch
  format and every preexisting signed record. Two real QUIC regressions cover
  production replanning around a live retry and a partial input upload whose
  volume goes offline before staging, then recovers after node reopen. All
  holders finish with zero staged receipts/reservations and exactly the expected
  used capacity, including two further reopens. Verification, activation, and
  checkpoint signing pass. The focused `retry` run passed all 16 selected tests
  locally; the full M5-104 gate is still required.

- [x] **M5-107 / P1 — Preserve verified placement across unrelated membership changes.**
  Final source audit found that activation dispatch aborts every uncommitted
  old-epoch verifier result, even when all shard holders and their authenticated
  domains are still current. Relabeling an unused member therefore discards
  already verified work. Replanning can then collide with retained immutable
  attempt/group evidence: the initial attempt ID excludes membership epoch,
  while replay correctly distinguishes epochs. The new real QUIC regression
  reproduced this on `4f8c685`: after verification, an unrelated relabel and
  reopen caused production replanning to create a second launch rather than
  retain the verifier result. Preserve accepted verified evidence when current
  shard placement is valid, and use current quorum authority to commit it.
  Continue cleanup when current placement is invalid. Bind new initial IDs to
  membership epoch without rewriting historical signed plans; coalesce with
  valid existing launches/retries so rollout cannot duplicate group evidence.
  Gate exact signed-transcript preservation through verification, an unused
  member relabel, production replanning, reopen, activation/current checkpoint,
  capacity cleanup, and two more reopens; retain epoch-one IDs and distinguish
  later epochs for both compact and fully bound plans.
  The correction is implemented. The focused `retry` run passes all 17 tests;
  the exact transcript-preservation regression passes, including both reopens,
  as does the corrected migration regression. All 48 core tests pass, including
  identity separation for later epochs and epoch-one compatibility. The final
  committed-source M5-104 gate remains pending. That gate's first
  workspace attempt on `4f8c685` reported 261 node passes and two failing older
  capacity assertions that inspected an offline default volume. They now sum
  all volumes, matching the production fixture's actual storage layout. No
  remote compilation server is used.

  The M5-108/M5-109 follow-up also preserves accepted verifier evidence when a
  dispatched launch still exists across the membership change. Launch dispatch
  now hands accepted results to activation before considering epoch/expiry
  cleanup; it removes only redundant launch metadata. The real QUIC regression
  now retains the dispatched record across relabel/reopen, as production does.

- [x] **M5-108 / P1 — Renew expired durable launches after safe input cleanup.**
  Source-only review of `c4e97f8..1f3141e` on 2026-09-26 finds no same-epoch
  expiry transition for the new durable staging path. Production launches
  expire after 24 hours (`crates/mb-node/src/network/p2p.rs:12471`–`:12473`).
  If an input volume/holder is unavailable until after that deadline, launch
  claim still selects the original plan using authority-only validation
  (`crates/mb-node/src/node.rs:4155`–`:4180`). Dispatch cleans up only on an
  epoch change (`network/p2p.rs:6296`–`:6315`); otherwise it retries staging
  under that expired plan and persists another deferral (`:6318`–`:6339`).
  Input reserve/write/finalize check the current deadline through
  `validate_local_coding_information` (`node.rs:4840`–`:4845`, `:5796`–`:5806`;
  `crates/mb-core/src/guild.rs:569`–`:578`), so restoring every disk and peer
  cannot unblock it. Completed staging followed by unsuccessful delegation
  until expiry has the same problem: delegated enqueue rejects the plan
  (`node.rs:4289`–`:4294`), and
  no coordinator job exists to report failure and create a retry. The launch
  remains pending (`node.rs:4183`–`:4191`), suppressing lifecycle replanning.
  Direct re-enqueue with the deterministic initial ID also retains the old
  signed plan (`node.rs:4072`–`:4083`). Partial reservations or finalized staged
  inputs remain stranded and checkpoint coverage cannot finish.
  Add durable fencing and resumable expiry cleanup, then renew with a fresh
  identity and current authority without modifying historical signed bytes
  or discarding accepted verifier evidence. Gate partial and finalized input
  staging plus completed-staging/failed-delegation cases across same-epoch
  reopen after expiry. Drive the actual worker to verification, activation,
  checkpoint coverage, zero reservations/staged receipts, and exact expected
  capacity on all holders, including two further reopens. The existing staging
  restart fixture restores its volume before launch expiry. This review ran
  no builds, tests, or runtime probes.

  The correction fences expired launches before resumable cleanup, preserving
  signed history and rejecting late results. Renewal atomically stores its
  successor link, a fresh signed launch, and required input descriptors; an
  already queued live replacement is reused. Replanning preserves an outstanding
  cleanup transition and never recreates a retired deterministic initial ID.
  Input descriptors now survive completed staging until activation or failure,
  with a plan-hash-bound completion marker to avoid repeating successful uploads.
  Accepted verifier evidence takes priority over launch cleanup. Node regression
  coverage includes the crash window between successor persistence and parent
  deletion, repeated reopen, and retired-ID replanning. Three real QUIC cases
  exercise partial staging, finalized staging, and completed staging with an
  actual coordinator shutdown, followed by same-epoch expiry/reopen and fresh
  activation/checkpoint coverage. The offline-volume cases also interrupt expiry
  cleanup and retain its fence across reopen. All cases assert exact successor
  transcript identity, immutable retired evidence, zero staged receipts and
  reservations, expected aggregate capacity on every holder, and two further
  reopens. Final focused validation passes: all 17 `retry` tests in 35.46 seconds
  and all four `launch_` tests in 69.49 seconds, including the dispatched-record
  membership-change case. The complete final M5-104 gate remains required.

- [x] **M5-109 / P1 — Give deferred launches bounded scheduling turns.**
  Source-only review of `c4e97f8..1f3141e` on 2026-09-26 finds launch claims
  always return the first undispatched current-epoch record
  (`crates/mb-node/src/node.rs:4155`–`:4180`). Records are ordered by attempt ID
  (`crates/mb-store/src/database.rs:348`–`:355`). Staging deferral leaves that
  record undispatched and only updates its error (`node.rs:4255`–`:4280`;
  `crates/mb-node/src/network/p2p.rs:6323`–`:6339`). Every worker cycle invokes
  the same cursorless launch claim (`network/p2p.rs:6023`–`:6043`, `:6283`–`:6285`).
  A lower-ID launch awaiting an offline volume or information holder therefore
  hides later launches whose holders, capacity, and coordinators are available.
  Retry rotation and activation queue turns do not dispatch those other lanes.
  Add fair launch selection/backoff so deferred staging, delegation, and cleanup
  cannot monopolize launch dispatch. Preserve durable intents and immutable
  plans, with explicit blocked status. Gate two independent current-epoch
  launches in adverse ID order through the production worker: keep the first
  staging destination unavailable while the second verifies, activates, and
  reaches checkpoint coverage, then restore and finish the first. Cover
  repeated reopen and all holders' reservations, staged receipts, and used
  capacity. This review ran no builds, tests, or runtime probes.

  The correction rotates launch claims by attempt ID, including stale cleanup
  turns, and advances the worker cursor before staging or delegation. Deferral
  preserves the launch and its error while allowing the next eligible ID a turn.
  A real QUIC regression retains a lower-ID partial upload on an offline volume
  through reopen while another lane verifies, activates, and signs its covered
  checkpoint. Restoring the first destination then finishes its packed-input
  lane. Both groups remain active through two further reopens, with exact used
  capacity and no staged receipts/reservations on any holder. Final focused
  validation passes: all four `launch_` tests in 69.49 seconds and all 17 `retry`
  tests in 35.46 seconds. The complete final M5-104 gate remains required.

- [x] **M5-110 / P1 — Recover expired launches after successful delegation.**
  Source-only review of `1f3141e..16c28a5` on 2026-09-26 finds that the new
  launch expiry transition cannot handle a coordinator disappearing after
  acknowledging delegation. Successful dispatch calls `complete_coding_launch`
  (`crates/mb-node/src/network/p2p.rs:6415`–`:6422`), which retains the launch
  and sets `dispatched = true` (`crates/mb-node/src/node.rs:4414`–`:4415`,
  `:4477`–`:4493`). `claim_coding_launch_after` unconditionally skips such
  current-epoch jobs before checking any deadline (`node.rs:4213`–`:4216`).
  Therefore the worker never reaches the new expiry cleanup/renewal branch
  (`network/p2p.rs:6346`–`:6352`), even after the delegator reopens in the same
  epoch. A concrete case is an acknowledged remote coordinator that stops
  before submitting either verifier evidence or a signed failure, while all
  information/parity holders, alternative coordinators, and enough members
  to satisfy the configured quorum remain available.
  Only that remote coordinator can submit the normal failure report
  (`node.rs:5320`–`:5332`); its absence does not create a retry. The retained
  launch continues to count as pending (`node.rs:4369`–`:4376`), suppressing
  lifecycle replanning (`network/p2p.rs:7774`–`:7780`). Staged inputs and any
  partial parity remain stranded, and checkpoint coverage cannot finish.

  Make expired dispatched launches eligible for delegator-owned recovery.
  Preserve accepted verifier evidence before fencing late results; durably
  clean the old attempt and select reachable replacement coordinators without
  modifying its signed history or treating silence as attributable misconduct.
  Simply selecting the expired job is insufficient if renewal repeatedly
  copies the unavailable coordinator. Gate actual successful remote delegation
  followed by coordinator shutdown before result/failure submission, expiry,
  and same-epoch delegator reopen under an explicitly configured majority
  quorum. Keep the old coordinator unavailable while
  the production worker reaches fresh verification, activation, and checkpoint
  coverage. Assert immutable retired evidence, rejection of late old results,
  zero reservations/staged receipts, exact capacity on every holder, and two
  further reopens. Also retain the accepted-verifier-result case across expiry.
  The three new expiry regressions exercise unsuccessful dispatch and leave
  their launch undispatched (`network/p2p.rs:22901`–`:22913`); they do not cover
  this acknowledged-delegation window. This review ran no builds, tests,
  daemons, runtime probes, or remote compilation.

  The correction selects expired dispatched launches for delegator-owned
  cleanup and renewal. Cleanup deferral retains the acknowledgement flag;
  fresh-role selection excludes the silent attempt's coordinator pair and
  ranks reachable authenticated peers. Persisted successors and existing live
  replacements are reused without repeating selection. Accepted verifier
  evidence retains priority over retirement. The real QUIC coordinator-loss
  regression passes in 88.95 seconds: delegation is acknowledged, a partial
  parity upload exists, the coordinator stops before reporting, and expiry
  cleanup is interrupted by an offline input volume. Same-epoch reopen under
  a previously configured majority quorum then reaches fresh verification,
  activation, and checkpoint coverage while that coordinator remains offline.
  Both replacement roles differ from both old roles. All holders have exact
  expected used capacity and no staged receipts/reservations after two more
  reopens. The accepted-result expiry/reopen regression also passes. The node
  lineage regression passes in 16.43 seconds, including retained acknowledgement
  across deferral, valid late-result rejection, and successor reuse after the
  persistence/parent-removal crash window. Its transcript helper records a
  verification time within the historical plan deadline. The complete final
  M5-104 workspace/provisioned gate remains required. All validation is local.
  The first complete workspace run on `4039bd6` passed strict Clippy, 48 core
  tests, and 268 node tests, but the two new expiry fixtures failed because
  their three-/fifteen-second deadlines elapsed during acknowledged dispatch
  or verification under concurrent suite load. Their initial immutable plans
  now allow 120 seconds for successful setup, then wait through the actual
  signed deadline before exercising expiry. Production deadlines and recovery
  behavior are unchanged. A new complete committed-source gate is required.
  The final ownership audit also found that same-ID replanning cleared the
  acknowledgement and deferral before retirement. Re-enqueue now preserves
  the entire durable owner's state, so expired acknowledged work still selects
  fresh roles and an explicit cleanup error survives replanning. The lineage
  regression proposes fresh signed bytes under the same deterministic ID
  before fencing, reopens, and checks the exact original plan, acknowledgement,
  and error before renewal. It passes locally in 16.36 seconds. The complete
  final gate must cover this ownership correction too.

- [x] **M5-111 / P1 — Fence stale cleanup against concurrent verifier acceptance.**
  `dispatch_next_coding_launch_after` checks accepted evidence once
  (`crates/mb-node/src/network/p2p.rs:6305`), then reads membership separately
  and invokes stale cleanup without retiring the signed attempt (`:6319`–`:6336`).
  After the initial check, the assigned coder can submit a valid historical
  transcript: `accept_coding_transcript` validates historical authority and
  persists an incomplete activation while no retirement/retry fence exists
  (`crates/mb-node/src/node.rs:5314`–`:5346`, `:6063`). With an unrelated member
  relabel, all information/parity placements can still be valid. Cleanup then
  discards their staged objects (`network/p2p.rs:7179`–`:7204`). The holder guard
  protects only a persisted transcript for an already committed group, not the
  pending activation (`node.rs:5938`–`:5952`; `volume.rs:1139`). Activation still
  requires the removed parity (`node.rs:5918`), defers indefinitely, and remains
  pending across reopen, suppressing checkpoint replanning (`node.rs:4392`;
  `network/p2p.rs:6189`–`:6238`). The existing verified-membership fixture accepts
  its transcript before cleanup starts, so it bypasses this arrival window.

  Arbitrate accepted-evidence ownership and retirement atomically before any
  holder cleanup. Preserve activation when it wins; otherwise durably fence
  the exact signed attempt so subsequent submissions cannot be accepted for
  deleted data. Apply the same ownership rule to stale delegated cleanup
  (`network/p2p.rs:6048`), preserving immutable signed history and valid current
  placements. Gate controlled transcript arrival after the initial evidence
  check, with both acceptance-before-retirement and retirement-before-acceptance
  orderings, an unrelated relabel, interrupted cleanup, reopen, production
  activation/checkpoint coverage, late-result rejection, all holders' exact
  capacity/receipt cleanup, and repeated reopen. This finding is source-only.

- [x] **M5-112 / P1 — Handle failure ownership transfer during expired-launch recovery.**
  An expired acknowledged launch can be claimed (`network/p2p.rs:6295`) just
  before its coder's signed failure arrives. Historical failure acceptance
  creates a durable retry, then removes the launch and its input descriptors
  (`node.rs:5354`–`:5408`); a report signed before expiry may arrive afterward.
  Retirement checks activation but not this launch-to-retry transfer
  (`node.rs:5572`–`:5597`), so expiry cleanup continues with the claimed snapshot.
  Renewal rejects the missing launch (`node.rs:4297`–`:4299`). The error handler
  then tries to defer that deleted launch (`network/p2p.rs:6374`–`:6379`), and
  `defer_coding_launch` returns "coding launch job is unavailable"
  (`node.rs:4494`–`:4500`). The error propagates out of the shared worker
  (`network/p2p.rs:6029`), completes the daemon's main select, and shuts down its
  network/control service (`cmd/mutualbackup/src/bin/mutualbackupd.rs:140`–`:192`).
  The coordinator-loss regression keeps the coder offline before recovery;
  it does not deliver a failure between claim and retirement.

  Reconcile the claimed launch with its current durable owner when fencing,
  renewing, and deferring. Treat an authenticated transition to retry/activation
  as normal progress, preserving its evidence and cleanup responsibility;
  never recreate the deleted owner or turn this routine race into daemon exit.
  Gate signed failure arrival after expired acknowledged claim and before
  retirement, including cleanup/selection deferral and same-epoch reopen.
  Assert that the worker/daemon remain alive, unrelated work progresses, the
  retry reaches fresh verification/activation/checkpoint coverage, historical
  plans stay immutable, and all holders finish without leaked staged objects,
  receipts or reservations after repeated reopen. This finding is source-only.

- [x] **M5-113 / P1 — Restage packed information for signed-failure retry successors.**
  Packed lanes can place information on a holder other than the delegator
  (`network/p2p.rs:12368`–`:12385`), while their initial coder is the delegator
  (`:6866`–`:6889`, `:12666`). Initial launch staging uploads those packed bytes
  under attempt A (`:6393`, `:12713`). If coding fails before verification,
  ordinary failure cleanup deletes A's information and parity objects
  (`:6136`, `:7179`–`:7204`; `volume.rs:1139`;
  `crates/mb-store/src/database.rs:2263`–`:2274`). Failure acceptance also deletes
  the durable packed-input descriptors (`node.rs:5406`, `:4451`–`:4456`).
  `execute_coding_retry` selects fresh roles excluding A's coder/verifier and
  delegates B without calling the information-staging helper
  (`network/p2p.rs:6534`–`:6665`). B fetches from its local source/cache or the
  named information holder, never from the delegator's surviving packed cache
  (`:7079`–`:7126`). A remotely placed new packed sector has no local source
  recipe or READY copy on that holder; `coding_information_range` therefore
  opens B's staged object, which was never uploaded (`node.rs:5039`–`:5070`).
  Healthy peers/disks do not resolve this missing-input retry. Coalescing a
  live successor also creates no launch/staging intent (`node.rs:4015`–`:4039`).
  The current retry fixture installs legacy source bytes on the information
  owner (`network/p2p.rs:22512`), masking this packed-only placement case.

  Retain recoverable packed-input intent across signed failure, transfer it
  durably to the selected successor, and repeat/resume all required information
  uploads under its new ID before delegation. READY inputs may be reused when
  independently authenticated and durable; never depend on discarded parent
  receipts. Gate a real production packed lane with a nonzero information
  sector on a holder that has no source/cache/READY copy, inject failure after
  initial staging, and keep the original coder out of the first replacement
  pair. Cover partial successor upload, an offline input volume, coalesced
  replanning, same-epoch reopen, fresh verification/activation/checkpoint
  coverage, immutable signed history, exact capacity on every holder, and zero
  staged receipts/reservations through repeated reopen. This finding is
  source-only.

  Implementation update (2026-09-26): signed-failure acceptance now atomically
  retains input intent and publishes retry ownership while deleting the old
  launch/staging marker. Successor preparation commits its immutable plan and
  input descriptors together. Retry execution cleans the parent, resumes all
  successor input uploads under the selected ID, and marks staging complete
  before delegation. Partial/offline uploads defer the same durable successor;
  coalesced replanning does not create another launch. A further signed failure
  transfers intent to its own retry before dropping parent metadata. Terminal
  activation/cleanup releases input records atomically; dispatch acknowledgement
  keeps them. Existing descriptor-less failed jobs can recover authenticated
  descriptors from the delegator's packed cache. Input intent pins that cache
  through unrelated checkpoint GC until terminal cleanup.

  The real packed-lane regression passes locally in 108.45 seconds. Actual
  production packing/placement puts two nonzero inputs on holders with no
  source/cache/READY copies; the initial coder is the delegator. After initial
  input staging, the production failure path cleans the parent and accepts its
  signed report. A fresh pair excludes both initial roles. Real partial input
  and parity uploads, an offline input volume, coalesced replanning, same-epoch
  reopen, verifier acceptance, activation and checkpoint coverage all pass.
  Every holder has exact expected capacity and zero staged receipts/reservations
  after two more reopens, with immutable plans/failure retained and input intent
  released. The test also exposed cached reservation offsets: information and
  parity reservations now recheck their current durable cursor on every request
  rather than replaying a journaled old offset, including after reopen.

  All 13 retry regressions pass together (102.86 seconds), including existing
  expiry, lineage, staging, membership and unrelated-work cases. Durable-history
  migration passes (19.48 seconds). The cache/GC regression passes (40.44
  seconds), retaining the packed copy across advancing unrelated checkpoints
  and reopen, then collecting it after terminal cleanup. The store rollback/
  reopen test passes (0.70 seconds), proving failed ownership transactions do
  not publish partial retry/input state or delete the launch. Strict locked
  mb-node/mb-store all-target Clippy passes (14.83 seconds), and formatting
  passes. Logs are `/tmp/mutualbackup-m5-113-*`; failed development runs are
  not passing evidence. Cleanup/submission corrections were committed as
  `6cbe822`. M5-116's acknowledged-successor recovery gap and the complete
  final M5-114 gate remain open. All builds and runs were local.

- [x] **M5-115 / P1 — Finish retired delegated submissions without starving stale cleanup.**
  Source-only review on 2026-09-26 covers `d3fd117` plus the pending cleanup
  ownership changes. The new stale-job branch deliberately excludes
  `Submitting` (`crates/mb-node/src/network/p2p.rs:6067`–`:6071`), allowing a
  valid historical result to be delivered. However, the delegator may already
  have retired that exact attempt during stale launch or expiry cleanup before
  delivery. `accept_coding_transcript` permanently rejects results behind the
  durable retirement fence (`crates/mb-node/src/node.rs:5384`–`:5390`). The
  submission error path only logs and sleeps (`network/p2p.rs:6148`–`:6162`);
  it never reconciles retirement or changes the durable `Submitting` state.
  `claim_delegated_coding` selects the first unfinished stale job without a
  cursor (`node.rs:4643`–`:4646`, `:4682`), so that job is selected forever
  when no current-epoch work is present. Later stale jobs cannot clean their
  staged objects or reservations. Reopening retains the same stuck owner.
  Current-epoch work is preferred by the claim loop, but this does not unblock
  the stale cleanup queue.

  After unsuccessful delivery, reconcile the exact signed attempt with its
  delegator's authenticated durable decision. If retirement won, resume safe
  cleanup and finish the redundant delegated job; if accepted evidence won,
  preserve activation data and finish or confirm idempotent delivery. Keep
  transient transport errors retryable, and never infer permission to delete
  from a timeout or an arbitrary submission error. Preserve valid historical
  submission when no fence exists. Gate a real durable `Submitting` job with
  retirement before delivery, an unrelated epoch change, a second stale job
  requiring cleanup, interrupted/offline cleanup and repeated reopen. Assert
  both jobs finish, worker liveness, exact holder capacity, no leaked receipts
  or reservations, and the acceptance-before-retirement ordering too. The
  existing new retirement fixture submits directly without persisting a coder
  `Submitting` job, so it does not cover this production path. No builds or
  runtime validation were run in this review.

  Status at that source-only review: the pending source adds delegator-owned retirement for
  M5-111 and recognizes retry/activation ownership transfer for M5-112,
  including focused regression sources. These corrections are uncommitted
  and not closed by this review; M5-115 remains in the delegated submission
  path. M5-113 remains unchanged: failure acceptance still deletes packed
  input intent (`node.rs:5464`), successor preparation stores only the retry
  job (`:5557`–`:5561`), and `execute_coding_retry` delegates without restaging
  (`network/p2p.rs:6714`–`:6722`). M5-112's new fixture also needs the requested
  assertion that unrelated coding work progresses alongside the failure race;
  its new failure branch exercises replacement coverage but creates no such
  unrelated lane. M5-114 still requires the complete final committed-tree gate.

  Implementation update (2026-09-26): M5-111, M5-112 and M5-115 now have
  focused local corrections. Stale launch cleanup and stale delegated cleanup
  arbitrate retirement at the delegator before touching holders. Verified
  activation wins that arbitration; retirement persists the exact signed plan
  before interrupted cleanup, and later results cannot claim discarded data.
  Expired claimed launches yield to authenticated retry/activation ownership,
  including late acknowledgement/deferral and a crash leaving a redundant
  launch beside its durable retry. The redundant launch is removed without
  removing input intent owned by that retry. Missing owners without evidence
  remain errors rather than being silently recreated.

  Durable historical Submitting jobs still deliver valid results. On failed
  delivery they query an existing matching retirement fence, without creating
  one or caching a negative answer. A confirmed fence permits resumed cleanup
  and completion; a transport error or an unfenced answer keeps delivery
  retryable. The new peer variants are appended to preserve existing Postcard
  discriminants, with matching CDDL and both transport frame checks. Signed
  record fields and persisted job encodings remain unchanged.

  Five stale regressions pass locally (44.74 seconds), covering result arrival
  after the launch guard, accepted durable delegated submission, retirement
  before submission, a second stale cleanup job, an offline volume, reopen,
  production verification/activation/checkpoint coverage and all holders'
  capacity/receipt/reservation cleanup. The failure-after-expired-claim test
  passes (151.47 seconds), with actual signed failure delivery, unrelated
  coding progress, live workers, fresh successor roles, late-result rejection
  and two further reopens. The lineage ownership test passes (7.40 seconds),
  including both failure/retirement orderings and redundant-owner recovery;
  legacy durable-history migration passes (15.74 seconds), including exact
  fence queries and rejected conflicting plans; both transport/CDDL frame and
  old-layout checks pass (6.22 seconds). Strict locked mb-node all-target
  Clippy and formatting pass. Failed development runs exposed and corrected
  fixture capacity/configuration assumptions and cached status reads; these
  are not passing evidence. Logs use `/tmp/mutualbackup-m5-cleanup-*`,
  `/tmp/mutualbackup-m5-115-stale-v6.log`, and
  `/tmp/mutualbackup-m5-112-failure-unrelated-v2.log`. M5-113 and the complete
  exact-commit M5-114 gate remain open. All builds and runs are local.

- [x] **M5-116 / P1 — Recover acknowledged retry successors after silence or epoch change.**
  The input-intent audit during M5-113 implementation found a separate owner
  gap. `process_coding_retry_job` completes the parent when successor delegation
  returns an acknowledgement (`crates/mb-node/src/network/p2p.rs:6252`;
  `:6673`). `claim_coding_retry` skips that completed parent forever
  (`crates/mb-node/src/node.rs:5536`), so its existing successor-expiry branch
  cannot run if the new coder disappears before sending result/failure.
  No launch job is created for that acknowledged successor. Checkpoint coverage
  keeps waiting (`network/p2p.rs:12964`), and coalescing alone does not create
  a new owner. Retained input intent now makes recovery possible but cannot
  make this unreachable worker transition execute. A completed parent can
  also retain cleanup/input ownership through an epoch change when its child
  has no accepted submission.

  Distinguish delegation acknowledgement from terminal completion when
  selecting durable retry ownership. Make acknowledged expiry and stale
  cleanup reachable without repeatedly dispatching a live successor or
  reopening terminal history. Prefer accepted child activation/failure over
  cleanup; preserve exact signed parent and successor history, reclaim
  unfinished staging before renewal, and retain recoverable input intent
  until the next owner takes it durably. Gate a real remotely placed packed
  successor acknowledged before coordinator silence, its actual signed
  deadline, same-epoch reopen, fresh replacement roles, verifier acceptance,
  activation/checkpoint coverage, all holders' exact capacity and no staged
  receipts/reservations through repeated reopen. Include accepted evidence
  and stale acknowledged ownership so completed cleanup does not loop.
  This finding is from source inspection; correction and validation are pending.

  Source-only follow-up (2026-09-26, `687e207` plus working tree): the pending
  claim path reopens completed parents when their unsubmitted child expires or
  becomes stale. Exact signed-child hashes bind terminal metadata; accepted
  activation/failure owners take priority, and late parent completion preserves
  child-owned input intent. New regression sources cover acknowledged packed
  expiry/reopen and accepted/stale ownership. These source changes remain
  uncommitted and are not closed by this review. The descriptor-less,
  retirement-before-cleanup schedule below is still unsafe; the new ownership
  test installs `Some(BTreeMap::new())` and does not exercise absent intent or
  interrupted remote cleanup after an independently established fence.

- [x] **M5-117 / P2 — Do not infer completed retry cleanup from absent input intent.**
  In the pending M5-116 source, `coding_retry_needs_recovery` treats an exact
  child retirement fence plus absent parent/child `coding-launch-information`
  records as terminal cleanup (`crates/mb-node/src/node.rs:5606`–`:5629`). It
  writes `coding-retry-terminal` and leaves the acknowledged parent complete,
  so all later claims skip it, including after reopen (`:5546`, `:5568`).
  Descriptor-less retries are supported: `coding_retry_information` returns
  None when no retained descriptors or packed cache exist (`:5707`–`:5745`),
  and successor preparation then creates no input-intent record (`:5748`–`:5765`).
  Those absent records say nothing about a coder's staged parity or partial
  reservation on another holder.

  A retirement fence precedes deletion rather than acknowledging it:
  `retire_delegated_coding_attempt` only persists the signed fence
  (`node.rs:5877`–`:5911`), and the stale coder awaits retirement before
  `abort_stale_delegated_coding` (`network/p2p.rs:6092`–`:6108`). Start with
  a descriptor-less retry A whose successor B was acknowledged and has staged
  parity. Advance membership without invalidating those holders. B's coder
  requests retirement, then stops after the delegator commits that fence and
  before any holder cleanup. A remains complete, neither input-intent record
  exists, and the next delegator claim permanently marks A terminal instead
  of cleaning B. With that coder unavailable, staged bytes, receipts and
  reservations have no reachable delegator cleanup owner; repeated cases
  consume storage capacity. Waiting through B's deadline or reopening does
  not repair the terminal marker.

  Keep fenced but unconfirmed cleanup recoverable regardless of whether packed
  input intent exists. Persist terminal cleanup evidence only after required
  holder cleanup succeeds, or after authenticated submission ownership takes
  over. Older completed histories without explicit cleanup evidence can be
  reconciled once rather than being declared clean from missing descriptors.
  Preserve accepted results/failures, exact signed history, and quiescent live
  acknowledgements. Add a real descriptor-less acknowledged-successor case
  with staged parity/partial reservations, unrelated epoch change, retirement
  committed before coder shutdown, interrupted/offline holder cleanup and
  delegator reopen. Keep the coder offline and assert delegator cleanup
  converges, every holder's exact capacity and zero staged receipts/reservations,
  and terminal history remains complete through repeated reopen. This finding
  is source-only and applies to the uncommitted M5-116 correction.

  Implementation update (2026-09-26): recovery no longer interprets absent
  descriptors as cleanup confirmation. A signed fence makes acknowledged work
  eligible immediately, even before its deadline. The worker distinguishes
  delegation acknowledgement from successful holder cleanup; delayed
  acknowledgement cannot delete input intent or publish a terminal marker just
  because another actor retired the child. Explicit cleanup completion checks
  the exact fence and publishes terminal history atomically with metadata
  release. Already accepted child result/failure ownership takes priority and
  preserves the child's own retry inputs. Existing descriptor-less histories
  without terminal evidence are reconciled once rather than silently skipped.

  The new real QUIC fixture acknowledges a descriptor-less successor, finishes
  one parity row and partially uploads another on different holders, advances
  an unrelated member's epoch, and retires the successor through the actual
  coder-to-delegator request. The coder's network then stops before deletion.
  A delayed parent acknowledgement leaves cleanup reachable. An offline holder
  defers the delegator's production cleanup; reopen retains that exact job.
  Restoring the volume and starting only the delegator's worker clears all
  holder bytes, receipts and reservations with the coder still offline. Two
  further reopens retain exact signed failure/successor/fence history and leave
  terminal cleanup unclaimed. The controlled ownership regression also covers
  expiry, stale acknowledgement, accepted child activation/failure, absent
  descriptors, and retirement before a late acknowledgement with retained
  packed intent. Both result/failure ownership and terminal cleanup survive
  repeated reopen.

  Final focused validation for M5-116/M5-117 passes locally: all 17 `retry_`
  tests pass together in 382.28 seconds, including actual signed packed-child
  expiry, silent coder/reopen, fresh roles, verifier acceptance, activation and
  checkpoint coverage, all-holder exact capacity and repeated cleanup checks.
  The suite also covers the new descriptor-less coder-shutdown schedule, all
  six controlled ownership cases, existing staging/fairness/history cases and
  packed cache lifetime. Strict locked mb-node/mb-store all-target Clippy passes
  in 38.80 seconds; formatting and whitespace checks pass. Logs are
  `/tmp/mutualbackup-m5-116-117-retries-v2.log` and
  `/tmp/mutualbackup-m5-116-117-clippy-v4.log`. Earlier development runs predate
  the separate acknowledgement/cleanup correction and are not final evidence;
  failed Clippy runs identified corrected style issues. Final source inspection
  finds no remaining blocker in these ownership/cleanup corrections. The full
  exact-commit M5-114 workspace and fresh provisioned acceptance gate remain
  required. All builds and runs were local.

- [x] **M5-118 / P1 — Reuse live retry ownership during expired-launch renewal.**
  The first full M5-114 workspace run on `3e5a7e3` passes strict workspace
  Clippy, formatting, all 48 core tests and 275 node tests, but four launch
  expiry regressions fail at the exact-successor assertion
  (`crates/mb-node/src/network/p2p.rs:25444`). The recovered acknowledged retry
  creates a live format-3 successor before the worker visits a same-lane expired
  launch. `coding_launch_renewal_candidate` searches only `coding-launch-job`
  (`crates/mb-node/src/node.rs:4329`–`:4356`); renewal directly publishes a new
  launch and staging intent without checking live retry/activation ownership
  (`:4396`–`:4440`). It therefore creates a second independently delegated
  successor even though the retry already owns progress. Coverage can activate
  the retry child while launch lineage points at the other child, allowing
  duplicate groups/uploads and unfinished staging rather than the milestone's
  coalesced ownership and bounded storage/transfer behavior.

  Include authenticated live retry children and accepted verified activation
  in renewal selection, with accepted valid coverage taking priority. Link the
  retired parent to the existing signed owner without creating another launch
  or mutating retry acknowledgement/history. Transfer still-needed input intent
  atomically, preserving accepted/terminal metadata and cache lifetime. Retain
  fresh coordinator selection for actual new work, exact signed lineage,
  interrupted cleanup/reopen and late-result rejection. Extend controlled node
  ownership checks through retry-first renewal, activation arrival during
  renewal and repeated reopen. Keep the four real launch regressions' exact
  successor, capacity/receipt/reservation and checkpoint assertions; do not
  relax them to accept duplicate ownership. Then rerun M5-114 completely on the
  final committed source. The failed workspace log is
  `/tmp/mutualbackup-m5-114-workspace-v1.log`; node runtime was 436.14 seconds.
  Workspace tests stopped at the node failure, so later suites and Docker lab
  safety did not run. Fresh Btrfs/network acceptance has not begun and no
  provisioned resources were created. All compilation and execution were local.

  Implemented on 2026-09-27: renewal now selects accepted verified activation,
  then a live authenticated retry child, then an existing launch. It links the
  retired launch to that exact signed owner and atomically transfers any missing
  input intent needed for unfinished work without creating a second launch.
  A durable expired launch also keeps priority over retry replanning while its
  cleanup and renewal remain pending. Controlled node assertions verify retry
  and activation ownership, input handling, history, and two reopens. All eight
  focused launch tests pass, including the four previously failing real QUIC
  cases with exact successor/capacity/checkpoint assertions unchanged; the
  controlled ownership test, strict locked mb-node/mb-store all-target Clippy,
  formatting, and whitespace checks pass. Logs are
  `/tmp/mutualbackup-m5-118-launches-v1.log`,
  `/tmp/mutualbackup-m5-118-unit-v1.log`, and
  `/tmp/mutualbackup-m5-118-clippy-v1.log`. The later M5-114 gate passed on
  `720920d`.

- [x] **M5-114 / gate — Recheck Milestone 5 after cleanup ownership and packed retries.**
  Correct M5-111 through M5-113 and M5-115 through M5-118, then source-review
  the final committed tree and run their controlled production-worker
  regressions locally. On that exact source, pass strict locked all-target
  workspace Clippy, locked
  all-target workspace tests, formatting, Docker lab safety, and the complete
  fresh disposable Btrfs/network acceptance script. Retain acknowledged expiry,
  accepted-result expiry/membership, staging, fairness, checkpoint, migration,
  relay/DCUtR, owner/storage-only recovery and bulk fallback coverage. Record
  exact commits and outcomes, and independently verify removal of all owned
  images/mounts, loop devices, namespaces, interfaces/rules and processes.
  Earlier M5-104 results remain historical; only this new gate can close the
  follow-up corrections. Build and run everything locally; never use a remote
  compilation server. The original source-only review did not execute the gate.

  Completed on 2026-09-28 against exact clean committed source
  `720920def00323c7efbcc347df8447e3e98fa6ec` after the M5-118 focused
  production-worker and controlled ownership checks. Formatting, strict locked
  all-target workspace Clippy, locked all-target workspace tests, and Docker
  lab safety passed. Workspace tests include 48 core, 279 node (10 ignored),
  51 store (14 ignored), CLI/application, and vendored targets. The node suite
  passed the four previously failing real launch-expiry regressions without
  weakening their exact-successor, cleanup/capacity, or checkpoint assertions.
  The complete fresh `scripts/reflink-acceptance.sh` run passed all 23
  invocations on a disposable local 8 GiB Btrfs image: repeated multi-owner
  QUIC passed in 749.36 seconds and the five-daemon seed/DHT recovery plus
  direct, DCUtR and relay fallback scenario passed in 2314.21 seconds.
  Runner cleanup exited zero. Independent post-run checks confirmed the owned
  `/tmp/mutualbackup-m5-114.aq7ldZ` image and mount were absent, `/dev/loop0`
  detached, namespaces and interfaces restored to baseline, forwarding
  restored, and no acceptance harness or daemon processes remained. The
  firewall contained only empty built-in tables materialized by the run; no
  custom chains or rules remained. Workspace, acceptance, and independent
  cleanup evidence are in `/tmp/mutualbackup-m5-114-workspace-v2.log`,
  `/tmp/mutualbackup-m5-114-provisioned-v1.log`, and
  `/tmp/mutualbackup-m5-114-cleanup-audit-v2.log`. The worktree stayed clean
  throughout both gates. No remote compilation server was used. Milestone 5
  was closed at this exact-source gate; the later M5-119 through M5-121 review
  reopens it without changing the tested source.

- [x] **M5-119 / P1 — Keep negative verifier evidence distinct from successful
  coverage and retry completion.** `replay_coding_transcript` can return an
  authenticated `InvalidOpening` or `InvalidCoding` finding, and
  `accept_coding_transcript` stores that result in a `coding-activation-job`
  (`crates/mb-core/src/attempt.rs:664`, `crates/mb-node/src/node.rs:5494`).
  `finish_coding_activation` correctly aborts its staged shards, but
  `complete_coding_activation` unconditionally writes retry-terminal metadata
  and deletes the parent's retained input intent (`node.rs:6291`, `:5840`).
  `coding_retry_has_replacement` also treats any replayable activation as a
  replacement (`node.rs:5915`), while same-lane replanning bails on that
  negative activation (`node.rs:4019`). A valid negative finding can therefore
  leave no protected group, discard the retry's inputs, and block a new
  attempt. Preserve the attributable finding as history, but only verified
  coverage may complete retry ownership; retain or recover input intent and
  allow a fresh authorized attempt. Gate negative opening and coding findings
  through cleanup, retry, replanning, checkpoint coverage, and repeated reopen.

  Completed in `6b7c79e`, `3d42888`, `520e73e`, and `4880c28`. Negative
  findings remain attributable history and requeue retry ownership only after
  holder abort; verified active group coverage alone can terminalize it.
  Retained input intent, same-lane replanning, checkpoint pending state,
  invalid-opening/invalid-coding evidence, production activation cleanup and
  repeated reopen have focused regressions. Completion now also handles a
  group retiring between activation and recording coverage.

- [x] **M5-120 / P1 — Coalesce legacy format-2 launch renewal with stronger
  format-3 ownership.** The migration fixture proves that a durable format-2
  launch and a new format-3 launch can coexist after reopen (`node.rs:15949`).
  After the format-3 launch fails into a live retry, expiry of the old launch
  cannot find that owner: `same_coding_lane` requires equal format versions
  (`node.rs:302`), and renewal clones the format-2 plan into another launch
  (`node.rs:4348`, `:4462`). Both can then compete for the same checkpoint,
  epoch, geometry and roots; for flat-root legacy input, the renewed format-2
  proof cannot establish full-root checkpoint coverage (`node.rs:7633`). Make
  the old launch yield directionally to a valid current format-3 retry,
  activation, or launch, without making format-3 work yield to weaker format-2
  evidence. When renewal has no stronger owner, upgrade eligible flat-root
  plans safely and preserve signed history. Gate old-launch/new-launch failure,
  retry, expiry, reopen, exact successor, checkpoint coverage and holder
  capacity.

  Completed in `6dc5c67` and `96560cc`. Renewal follows valid format-3
  activation, retry or launch ownership directionally, while an unowned legacy
  flat-root renewal upgrades to format 3. Controlled and real production-worker
  expiry regressions verify exact successor, retained input intent, repeated
  reopen and holder capacity.

- [x] **M5-121 / P1 — Retain cleanup obligations for offline removed holders.**
  Stale cleanup suppresses a failed abort RPC when the holder is absent from
  `active_members`, then reports success (`crates/mb-node/src/network/p2p.rs:7367`,
  `:7414`). Delegated, launch and retry owners can consequently complete or
  disappear while that holder still has staged parity, receipts or
  reservations (`p2p.rs:6108`, `:6246`, `:6910`). Holder storage is discarded
  only by an explicit abort (`node.rs:6467`, `volume.rs:1105`); reopening a
  previously offline holder does not consume the lost obligation. Preserve a
  durable per-holder cleanup obligation or sweep abandoned attempts during
  holder recovery without blocking current-membership progress. Gate removed
  offline holder return, repeated reopen, and exact zero staged bytes,
  receipts and reservations.

  Completed in `0862134`. Inactive-holder abort failures write durable
  per-holder obligations; an independent daemon worker retries them with cached
  endpoints and deletes them only after acknowledgement. A real five-node
  removed/offline-holder regression returns the holder after repeated reopen
  and confirms zero staged bytes, receipts and reservations.

- [x] **M5-122 / gate — Recheck Milestone 5 after M5-119 through M5-121.**
  Correct the three source blockers, review the committed source, and run
  focused production-worker and reopen regressions for each ownership and
  cleanup path. On the exact corrected commit, pass local formatting, strict
  locked all-target workspace Clippy and tests, Docker lab safety, and the
  complete fresh disposable Btrfs/network acceptance gate. Independently
  confirm cleanup of owned images, mounts, loop devices, namespaces,
  interfaces/rules and processes. Record the exact commit and outcomes;
  M5-114 remains historical evidence only. Build and run locally, with no
  remote compilation server. The original source-only review did not execute
  M5-122.

  Passed on clean committed source `4880c28fbfce9a1654f970eb11e71d020e938b37`.
  Local formatting, strict locked all-target workspace Clippy, locked all-target
  workspace tests and Docker lab safety passed. The node suite had 284 passed,
  10 expected ignored; the core suite had 48 passed and store had 51 passed,
  14 expected ignored. All 23 fresh `scripts/reflink-acceptance.sh` invocations
  passed on a disposable local 8 GiB Btrfs image: repeated multi-owner QUIC
  passed in 585.81 seconds; five-daemon seed/DHT recovery with direct, DCUtR
  and relay fallback passed in 1976.51 seconds. Runner cleanup exited zero.
  Independent audit confirmed the owned image and mount absent, `/dev/loop0`
  detached, namespaces, interfaces, forwarding and firewall rules restored to
  baseline, and no acceptance harness or daemon process remained. Logs:
  `/tmp/mutualbackup-m5-122-workspace-v2.log`,
  `/tmp/mutualbackup-m5-122-provisioned-v2.log`, and
  `/tmp/mutualbackup-m5-122-cleanup-audit-v2.log`. All builds and runs were
  local. This gate closed Milestone 5 on that exact code commit; the later
  source-only review below reopens it. M5-114 remains historical evidence for
  its earlier tree.

- [x] **M5-123 / P1 — Replan an initial launch after negative verifier cleanup.**
  `complete_coding_activation(attempt, false)` requeues only a matching retry
  parent; when the negative finding belongs to an initial launch, it deletes
  that launch and its packed-input intent without creating a successor
  (`crates/mb-node/src/node.rs:6453`). Production `commit_backup_job` queues
  variable lanes once and then waits only for coverage (`network/p2p.rs:14318`,
  `:13144`). Lifecycle replanning skips a Running backup (`p2p.rs:8157`), so an
  uninterrupted daemon can wait forever with no coding owner after an
  authenticated `InvalidOpening` or `InvalidCoding` finding. A daemon restart
  may reclaim the backup; it is not a live retry policy. Retain or reconstruct
  the initial lane's input intent and create a fresh attempt after confirmed
  holder cleanup. Gate the production backup worker through negative evidence,
  cleanup, fresh launch, verified checkpoint coverage and uninterrupted wait.

  Corrected in `9cfa4b5`. Negative activation completion atomically creates a
  fresh signed launch and transfers its input intent after acknowledged holder
  cleanup. The production-worker regression drives an invalid opening through
  cleanup, live checkpoint wait, renewed verified coverage and reopen.

- [x] **M5-124 / P1 — Gate legacy renewal on pending negative activation cleanup.**
  An old format-2 launch and a format-3 activation can coexist for the same
  lane. `coding_launch_renewal_candidate` ignores a negative format-3
  activation awaiting abort (`node.rs:4427`); expiry renewal then writes a
  fresh launch directly (`node.rs:4534`), bypassing the negative-cleanup wait
  in `enqueue_coding_launch_with_information` (`node.rs:4038`). The daemon
  dispatches launches before processing activations (`p2p.rs:6052`), so a
  deferred abort can overlap the fresh launch and contend for holder capacity.
  Keep cleanup ownership across format versions and start renewal only after
  the negative attempt's holder cleanup is confirmed. Gate old launch expiry,
  pending invalid-opening/invalid-coding cleanup, constrained holder capacity,
  repeated reopen and exact successor lineage.

  Corrected in `9cfa4b5`. Cross-version renewal treats a pending negative
  activation as cleanup ownership and defers fresh launch creation until its
  holder abort is confirmed. The expiry/negative-cleanup worker regression and
  repeated-reopen checks pass.

- [x] **M5-125 / P1 — Recover a launch that yielded to activation without coverage.**
  Legacy renewal may record a pending verified format-3 activation as the old
  launch's successor (`node.rs:4427`, `:4534`). It transfers no input intent
  to an activation, then removes the old launch's intent (`node.rs:212`,
  `:4590`, `:4732`). If that group retires before activation completion, the
  worker cleans it as uncovered (`p2p.rs:6380`, `:6485`), but
  `complete_coding_activation(false)` requeues retry parents only
  (`node.rs:6453`). The signed launch successor is left as history with no
  live owner or pinned packed input for the pending checkpoint. Preserve a
  recoverable launch-parent intent until retained coverage is established, or
  requeue it after uncovered activation cleanup. Gate verified activation,
  legacy expiry/yield, retirement before completion, crash/reopen, renewed
  coverage and packed-input retention.

  Corrected in `9cfa4b5`, `dd942a6`, and `e09a13f`. Pending activation keeps
  the old launch's input, and uncovered completion atomically hands it to a
  successor. A retired group is re-encoded on an unused parity placement; if
  none exists, the pending job survives until eligible retirement history is
  forgotten. The live production-worker regression covers legacy yield,
  retirement, renewed coverage and reopen.

- [x] **M5-126 / P1 — Discover returned removed holders for cleanup.**
  The obligation worker adds addresses only from `guild-endpoints`
  (`node.rs:6761`, `p2p.rs:6108`). Membership events do not update that cache
  (`node.rs:2821`), and normal DHT/peer-exchange refresh queries active peers
  only (`p2p.rs:8863`, `:8904`). A dynamically added holder can have no cached
  address; after removal and an owner restart, a holder returning at a new
  address without an existing connection cannot receive its pending abort.
  The removed-holder regression manually injects the returned address
  (`p2p.rs:23778`), so it bypasses this discovery path. Resolve obligation
  holders by authenticated identity after removal, then clear the obligation
  only after abort acknowledgement. Gate added/removed holder return with
  address change, no manual address injection, repeated reopen and exact zero
  staged bytes, receipts and reservations.

  Corrected in `9cfa4b5`. A removed holder publishes only its signed endpoint
  to DHT; the cleanup worker resolves that identity after cached/direct abort
  fails, then clears its obligation only after acknowledgement. The network
  return regression changes address without manual injection and verifies
  zero staged bytes, receipts and reservations through reopen.

- [x] **M5-127 / gate — Recheck Milestone 5 after M5-123 through M5-126.**
  Correct the source blockers, review the committed source and run focused
  production-worker and reopen regressions for each path. On the exact
  corrected commit, pass local formatting, strict locked all-target workspace
  Clippy and tests, Docker lab safety, and all fresh disposable Btrfs/network
  acceptance invocations. Independently confirm cleanup of owned images,
  mounts, loop devices, namespaces, interfaces/rules and processes. Record
  the exact commit and outcomes. M5-122 remains historical evidence only;
  build and run locally, with no remote compilation server. The source-only
  review that opened this gate did not execute M5-127.

  Passed on clean committed code source
  `e09a13f8fcdfca1626e04118a668f67e1c4208d9`. Focused production-worker
  and reopen regressions passed. Local formatting, strict locked all-target
  workspace Clippy and tests, and Docker lab safety passed; the node suite had
  286 passed and 10 expected ignored. All 23 invocations of the fresh local
  Btrfs/network acceptance suite passed on a disposable 8 GiB image. Repeated
  multi-owner QUIC passed in 788.94 seconds, and five-daemon seed/DHT recovery
  with direct, hole-punched and relay paths passed in 2331.72 seconds. The
  runner exited with cleanup result zero; an independent audit matched the
  baseline for namespaces, interfaces, loop devices, Btrfs mounts, forwarding
  and firewall rules, with no acceptance process or owned image remaining.
  The first disposable run used a mount without `user_subvol_rm_allowed` and
  failed a subvolume deletion test; its resources were removed, and the full
  corrected fresh run passed. Logs: `/tmp/mutualbackup-m5-127-workspace-final.log`,
  `/tmp/mutualbackup-m5-127-provisioned-v2.log`, and
  `/tmp/mutualbackup-m5-127-cleanup-audit.log`. All compilation and execution
  were local; no remote compilation server was used. That exact-source gate
  closed Milestone 5 at the time; the source-only review below reopens it.

- [x] **M5-128 / P1 — Keep retired full-width activation recoverable through
  forgetting.** Production chooses a `2+1` or `3+2` profile for three or five
  distinct domains, using every domain (`crates/mb-node/src/network/p2p.rs:12349`).
  If a verified group retires before its activation job completes, the worker
  acknowledges holder abort and calls `complete_coding_activation(false)`
  (`p2p.rs:6416`). With no unused parity placement, that method errors before
  recording a successor or completion (`crates/mb-node/src/node.rs:6570`,
  `:6604`). The error escapes the coding worker and the daemon's main task
  selection (`p2p.rs:6068`, `cmd/mutualbackup/src/bin/mutualbackupd.rs:143`).
  The abort has already finalized the retained group's attempt and deleted its
  attempt receipts (`node.rs:6810`, `crates/mb-node/src/volume.rs:1088`). If
  the daemon is restarted and the retired group is forgotten, the pending
  activation is treated as new; parity activation requires those deleted
  receipts (`node.rs:6777`, `volume.rs:1033`) and cannot complete. Defer a
  no-placement handoff without stopping the worker, and after eligible forget
  create a fresh signed attempt with retained input intent instead of replaying
  the old transcript. The M5-127 retirement regression uses a `1+1` profile
  across five nodes (`p2p.rs:24435`), so it always has a spare placement. Gate
  real full-width 3- and 5-domain production workers through retire,
  acknowledged cleanup, forget, renewed coverage, backup completion and
  repeated reopen. `561a438` retains the replan marker and packed input
  through cleanup; `dba09d0` makes a repeated holder abort recheck group state
  after Forget instead of replaying a cached pre-Forget acknowledgement. The
  committed worker regressions cover three and five domains, parity deletion
  after Forget, renewed coverage and repeated reopen. The provisioned Btrfs
  acceptance fixture in `ae081a3` also drives real backup commit through both
  full-width schedules and checks the committed checkpoint after two reopens.
  The exact-source M5-131 gate passed on `39a99e7`.

- [x] **M5-129 / P1 — Select a usable parity holder when replanning a retired
  group.** The new placement search takes the first active member that produces
  a valid, unused group ID (`crates/mb-node/src/node.rs:6574`), without the
  reachability and free-capacity checks used by initial placement
  (`crates/mb-node/src/network/p2p.rs:12566`, `:12606`, `:12462`). In a guild
  with spare domains, let the first eligible holder be full or offline while a
  later holder has capacity and a working path. The signed successor targets
  the unusable holder; its parity reservation fails (`p2p.rs:7291`) or active
  holder abort cannot be acknowledged (`p2p.rs:7530`). Failure retries and
  expiry renewal retain the same geometry (`node.rs:5873`, `:4572`), so the
  backup can wait indefinitely despite a viable placement. Replan against
  reachable capacity, and rotate geometry after a capacity or availability
  failure while preserving cleanup and input ownership. Cover a full and an
  offline first spare, a usable later spare, fresh coverage and reopen.
  `561a438` samples reachable capacity before retired activation replanning;
  `95962be` rotates geometry in retry and expiry renewal and retains active
  offline-holder cleanup obligations. The live regressions cover both a full
  first spare and an offline first spare, a usable later holder, renewed
  coverage and reopen (`1a34fce`). The exact-source M5-131 gate passed on
  `39a99e7`.

- [x] **M5-130 / P1 — Rotate coordinators after an initial negative verifier
  finding.** The no-retry-parent completion path clones the negative attempt's
  plan and changes only format, parity placement if necessary, attempt ID and
  expiry (`crates/mb-node/src/node.rs:6542`, `:6615`). It keeps the same coding
  coordinator and verifier. An initial `InvalidCoding` result from a persistently
  faulty coder can therefore be cleaned up and relaunched to that same coder
  forever, although healthy alternatives are reachable. Normal failure retry
  excludes the old coordinators (`network/p2p.rs:6936`); the documented coding
  invariant requires fresh coordinators after missing confirmation
  (`plan.md:2570`). Select fresh reachable roles for a negative initial result
  before signing its successor, retain the exact negative evidence and packed
  input intent, and cover repeated invalid-coding evidence followed by a
  healthy coordinator, verified coverage and reopen. Source-only follow-up on
  `7fea0e1` finds that its renewal selector excludes both old roles
  (`network/p2p.rs:6802`), and the new completion check also forbids either
  old role in either position (`node.rs:6660`). A three-member guild therefore
  has only one candidate for two distinct roles and waits indefinitely even
  when all members are healthy. Find a safe role rotation for the three-domain
  profile and test it through the production worker and reopen. The committed
  five-node regression alone does not close this task. `2affb17` excludes the
  blamed coder across same-source attempts, including after parity rotation.
  The three-member fallback rotates the old verifier into coding while
  excluding the old coder; the live worker regression processes two invalid
  transcripts before healthy coverage and reopen. The exact-source M5-131 gate
  passed on `39a99e7`.

- [x] **M5-131 / gate — Recheck Milestone 5 after M5-128 through M5-130.**
  Correct all three source blockers and review the committed source. Run focused
  production-worker, full-width placement, negative-evidence and reopen
  regressions. On the exact corrected code commit, pass local formatting,
  strict locked all-target workspace Clippy and tests, Docker lab safety, and
  all fresh disposable Btrfs/network acceptance invocations. Independently
  confirm cleanup of owned images, mounts, loop devices, namespaces,
  interfaces/rules and processes. Record the exact commit and outcomes.
  Passed on clean committed code source
  `39a99e7e7ef3f2865d05449bbae2ed25c444a4ad`. The first workspace run
  exposed six restart/cleanup regression assertions that still expected
  pre-handoff behavior. `39a99e7` updated them to verify immediate post-Forget
  parity removal, durable offline-holder obligations, exact successor lineage,
  cleanup after return and repeated reopen; all six focused reruns passed.
  Local formatting, strict locked all-target workspace Clippy and tests, and
  Docker lab safety passed; the node suite had 293 passed and 11 expected
  ignored. All 24 invocations of the fresh local Btrfs/network acceptance
  script passed on a disposable 8 GiB Btrfs image. Full-width three- and
  five-domain backup commit passed in 73.31 seconds, repeated multi-owner QUIC
  in 545.04 seconds, and five-daemon seed/DHT recovery with direct,
  hole-punched and relay paths in 1718.80 seconds. The runner exited with
  cleanup result zero. An independent audit matched the baseline for Btrfs
  mounts, loop devices, namespaces, interfaces, forwarding and firewall rules;
  no owned image root or acceptance process remained. Logs:
  `/tmp/mutualbackup-m5-131-workspace-v2.log`,
  `/tmp/mutualbackup-m5-131-clippy-v2.log`,
  `/tmp/mutualbackup-m5-131-docker-safety-v2.log`,
  `/tmp/mutualbackup-m5-131-provisioned.log`, and
  `/tmp/mutualbackup-m5-131-cleanup-audit.log`. All compilation and execution
  were local; no remote compilation server was used. This gate closed
  Milestone 5 at the time on its exact code source; the source-only review
  below reopens it. M5-127 remains historical evidence for `e09a13f`.

- [x] **M5-132 / P1 — Retain post-Forget cleanup ownership for retired READY
  parity.** A retired activation with a usable spare aborts its holders while
  the old group is still retained. `discard_coding_attempt` treats any retained
  group, including a retired one, as successful abort after only finalizing
  attempt receipts; it leaves READY parity and its volume receipt
  (`crates/mb-node/src/node.rs:7206-7222`). The delegator can then create the
  successor and complete the activation (`network/p2p.rs:6418-6454`,
  `node.rs:6800-6910`), dropping the only path that would send another abort
  after `ForgetCodingGroup`. Forget installs no holder cleanup
  (`node.rs:2892-2985`); it can also reach the delegator before a holder
  because event dissemination may defer to tail sync
  (`network/p2p.rs:8741-8764`). The response-cache bypass in `dba09d0` helps
  only if another abort is sent. A group added and forgotten before checkpoint
  commit is absent from the checkpoint and dynamic-state inputs used by
  checkpoint garbage collection (`node.rs:9357-9375`, `:9539-9585`), so its
  old parity can remain indefinitely and consume storage. Keep a durable
  holder cleanup obligation until forgetting is observed and deletion is
  acknowledged, or make Forget reliably schedule equivalent deletion on each
  holder. Regress the spare-placement path through Retire, successor creation,
  Forget, delayed holder sync, parity removal, and repeated reopen. `a7da0ce`
  records a holder-local durable cleanup obligation before finalizing any
  retained group's attempt receipts, including when the holder has not yet
  received Retire. Its cleanup worker waits for that holder's Forget, then
  removes READY parity and clears the obligation; a successful early local
  abort at the delegator no longer erases the obligation. The spare-placement
  regression now activates real READY parity and checks successor coverage,
  local and remote obligations, delayed holder Forget, removal and two reopens.
  The M5-134 exact-source gate passed.

- [x] **M5-133 / P1 — Exercise three-member negative-evidence rotation through
  the production worker.** M5-130 explicitly required a three-domain
  production-worker and reopen regression. The committed
  `three_member_negative_activation_rotates_verifier_into_coder` test only
  constructs a negative transcript and calls the coordinator selector
  (`network/p2p.rs:24570-24705`); it does not process the activation, create
  and run its successor, establish verified coverage, or reopen. The live
  two-negative-transcript coverage/reopen regression uses five active members
  (`network/p2p.rs:25471-25750`). Add the missing three-member worker path
  with holder cleanup, renewed attempt, verified coverage and repeated reopen;
  confirm the fallback works after an actual negative result rather than only
  when queried directly. `a7da0ce` extends the three-member regression with a
  real encrypted source sector and checkpoint, staged bad parity, negative
  activation cleanup, a renewed signed plan, production coding workers,
  verified checkpoint coverage and two reopens. The M5-134 gate passed.

- [x] **M5-134 / gate — Recheck Milestone 5 after M5-132 and M5-133.** Review
  both corrections and pass focused retained-group cleanup, delayed Forget,
  three-member negative-evidence, backup coverage and reopen regressions.
  Then run the complete local exact-source workspace, Docker safety,
  disposable Btrfs/network acceptance and independent resource-cleanup gate.
  Record the code commit and results. Passed on clean committed code source
  `a7da0ceb81ee1fa9c82dc3c7b9e7ee12998d684c`. Focused three-member
  negative activation, spare-placement cleanup, offline first spare, and
  three- and five-domain full-width regressions passed locally. Formatting,
  strict locked all-target workspace Clippy, and Docker lab safety passed.
  The first workspace run hit the shell's 1,024-file-descriptor limit in three
  parallel network tests; the unchanged source passed the complete locked
  all-target workspace run with a local soft limit of 8,192 (node suite: 293
  passed, 11 expected ignored). The first disposable Btrfs run exposed a mount
  setup omission: unprivileged subvolume deletion needs
  `user_subvol_rm_allowed`. A second fresh local 8 GiB image with that option
  passed all 24 `reflink-acceptance.sh` invocations. Full-width backup commit
  passed in 89.10 seconds, repeated multi-owner QUIC in 806.09 seconds, and
  five-daemon seed/DHT recovery with direct, hole-punched and relay paths in
  2484.54 seconds. The runner reported acceptance and cleanup result zero. An
  independent audit matched the pre-run baseline for mounts, loop devices,
  namespaces, links, forwarding and firewall rules; no owned image root or
  process remained. Logs: `/tmp/mutualbackup-m5-134-workspace-v2.log`,
  `/tmp/mutualbackup-m5-134-docker-safety.log`,
  `/tmp/mutualbackup-m5-134-provisioned-v2.log`, and
  `/tmp/mutualbackup-m5-134-cleanup-audit.log`. All compilation and execution
  were local, with no remote compilation server. This gate closed Milestone 5
  at that time; the source-only review below reopens it. M5-131 remains
  historical evidence for `39a99e7`.

- [x] **M5-135 / P1 — Preserve live READY information when retiring an old
  attempt.** The M5-132 cleanup records obligations for information owners as
  well as parity holders (`node.rs:7276-7306`). A successor can keep the same
  information sector while changing parity placement (`node.rs:6815-6853`),
  and explicitly reuses its existing READY information object without taking
  ownership of the old attempt (`node.rs:5399-5414`, `:5502-5518`,
  `:7124-7140`). Once the old group is forgotten, the holder cleanup worker
  calls `discard_coding_attempt` (`network/p2p.rs:6096-6117`), which invokes
  `discard_attempt` (`node.rs:7206-7248`). That scans every online volume and
  deletes all objects with the old attempt ID, including READY information
  used by the successor (`volume.rs:1105-1140`,
  `crates/mb-store/src/database.rs:2286-2307`). The old attempt receipts were
  finalized before Forget, so the information `volume-receipt` can remain
  pointing at a deleted object; only old parity gets explicit receipt cleanup
  (`node.rs:7220-7248`). If the source recipe is unavailable,
  `variable_shard_for_guild` can no longer serve that verified successor's
  information shard (`node.rs:7420-7464`). Make post-Forget cleanup distinguish
  retired parity from information still live in a successor or checkpoint, and
  keep object and receipt state consistent. Regress an activated successor
  reusing an old READY information shard through old-group Forget and cleanup,
  with the source recipe unavailable, then verify shard reads and repeated
  reopen. This review was source-only. Implemented in the M5-135/M5-136/M5-138
  source checkpoint: old-attempt cleanup retains READY information and its
  active receipt, and GC pins retained or pending successor information.
  Source-unavailable successor and repeated-reopen regressions passed locally;
  the complete M5-137 gate passed on committed code `666697a`.

- [x] **M5-136 / P1 — Give routinely forgotten groups a parity cleanup
  owner.** The new holder-local obligation is created by attempt abort
  (`node.rs:7206-7228`), but ordinary lifecycle retirement and forgetting
  only commit guild events (`network/p2p.rs:8490-8719`, `:8722-8775`); a
  successfully completed activation need not receive an abort. The lifecycle
  retires a redundant group when another group covers its still-live sectors,
  then forgets it. Before Forget, garbage collection regards that group's
  still-live sectors as making it live; after Forget the group is absent from
  dynamic state, the only input from which variable-group garbage candidates
  are derived (`node.rs:9388-9406`, `:9530-9594`). Its READY parity and
  volume receipt can therefore remain allocated indefinitely, even across
  later checkpoints. A later attempt with the same geometry also meets that
  old READY row under the same group ID and cannot stage a different attempt
  over it (`crates/mb-store/src/database.rs:2120-2153`). Persist cleanup
  ownership for every certified Forget, including completed groups, and
  remove old parity only after each holder has installed Forget; preserve
  information shared by live groups. Regress
  a completed Add, redundant Retire, Forget, delayed holder sync, parity
  removal and repeated reopen. This review was source-only. Implemented in the
  M5-135/M5-136/M5-138 source checkpoint: certified Forget atomically records
  holder cleanup obligations, and local cleanup waits for that holder's own
  Forget. The ordinary completed-group/delayed-holder network regression and
  repeated-reopen checks passed locally; M5-137 passed on `666697a`.

- [x] **M5-137 / gate — Recheck Milestone 5 after M5-135 and M5-136.** Review
  both cleanup paths and pass focused live-information retention, ordinary
  lifecycle Forget, delayed-holder and repeated-reopen regressions. Then run
  the complete local exact-source workspace, Docker safety, fresh disposable
  Btrfs/network acceptance and independent resource-cleanup gate before
  closing Milestone 5. Passed on clean committed code
  `666697aafca6a93cd76c0f54da47c7db4f8edf4a` (source implementation
  `9da97eb`, fixture shutdown stabilization `666697a`). Focused M5-135,
  M5-136, M5-138, same-group-ID successor, offline/online spare and repeated
  reopen regressions passed. Exact-source formatting, strict locked all-target
  workspace Clippy, Docker lab safety and the complete locked all-target
  workspace tests passed locally (node suite: 294 passed, 11 expected ignored).
  A fresh local 8 GiB Btrfs image mounted with `user_subvol_rm_allowed` passed
  all 24 `reflink-acceptance.sh` invocations: full-width QUIC backup (75.21s),
  repeated multi-owner QUIC backup (556.70s), and five-daemon seed/DHT
  recovery across direct, hole-punched and relay paths (2157.21s). The first
  immediate resource snapshot differed only in changing iptables timestamps
  and packet counters plus three transient veth links during namespace teardown.
  A subsequent independent audit found the owned image root gone, 31 baseline
  mounts, no loops or namespaces, the two baseline links, forwarding restored
  to zero, and no owned firewall chains or processes. Logs:
  `/tmp/mutualbackup-m5-137-workspace-v2.log`,
  `/tmp/mutualbackup-m5-137-format.log`,
  `/tmp/mutualbackup-m5-137-clippy.log`,
  `/tmp/mutualbackup-m5-137-docker-safety-v2.log`,
  `/tmp/mutualbackup-m5-137-provisioned.log`, and
  `/tmp/mutualbackup-m5-137-cleanup-audit-final.log`. All compilation and
  execution were local; no remote compilation server was used. This gate closed
  Milestone 5 at that time. M5-134 remains historical evidence for `a7da0ce`.

- [x] **M5-138 / P1 — Clean repaired parity after ordinary Forget.** Source-only
  review of the current uncommitted M5-135/M5-136 changes found that a parity
  shard repaired while its group is live is stored under the repair ID
  (`node.rs:7958-8061`). After Forget, `discard_coding_attempt` uses the
  original coding attempt ID (`node.rs:7275-7341`), and the new
  attempt-qualified removal deliberately skips that repaired READY row
  (`volume.rs:688-703`). The cleanup obligation can then be acknowledged even
  though the forgotten group's parity and receipt remain. The new historical
  transcript GC pass schedules only information-sector cleanup
  (`node.rs:9548-9572`); no routine path schedules the repaired parity after
  the group has left dynamic state. The existing node regression explicitly
  repairs this parity, then expects old-attempt cleanup to remove it
  (`node.rs:19424-19460`, `:19618-19645`); its final GC removal is manually
  scheduled by the test, not by the lifecycle. Make Forget cleanup retire
  repaired parity safely without deleting a successor attempt that reuses the
  group ID, and regress the repair/Forget/reopen path without manual GC setup.
  Implemented in the M5-135/M5-136/M5-138 source checkpoint: READY parity is
  matched to its verified transcript hash, so cleanup includes a later repair
  of the old group while preserving a successor with the same group ID and
  different evidence. Object and repair receipts are removed together. The
  repair/Forget regression now checks receipts and two reopens without manual
  GC setup. Focused tests and the full M5-137 gate passed on `666697a`.

- [x] **M5-139 / P1 — Transfer same-ID successor receipts across volumes.**
  A successor may stage on less-used volume B while the old group's active
  receipt points to A (`volume.rs:780-829`, `:878-902`). Activation makes B's
  row READY before rejecting A's conflicting receipt (`volume.rs:1090-1141`).
  Delayed old-attempt cleanup removes A, sees the newer READY row on B, retains A's
  receipt, and reports completion (`volume.rs:693-741`). Reads then follow the
  removed A row, and activation retries keep failing. The existing same-ID
  regression uses one volume and cleans the old attempt before staging its
  successor (`node.rs:17261-17321`). Make receipt handoff and old cleanup
  atomic or replayable across volumes. Regress two-volume delayed cleanup,
  successor activation/read with the source unavailable, and repeated reopen.
  Implemented in `7392e6d`: activation records cleanup ownership for the old
  volume and publishes the new READY receipt; old cleanup cannot acknowledge
  while its active receipt still points away from a newer READY copy. A
  two-volume interruption/retry/cleanup/reopen regression passed locally.

- [x] **M5-140 / P1 — Bind historical Add replay and Forget cleanup to the
  original attempt.** After old Forget, a same-ID successor overwrites the
  group-key transcript (`node.rs:3083-3117`), but event-tail catch-up fetches
  evidence for an earlier Add by group ID alone (`network/p2p.rs:9015-9027`,
  `:9093-9107`). Event installation accepts a replayable transcript with the
  same group, without binding it to that Add's attempt (`node.rs:3054-3068`).
  The earlier Forget then schedules cleanup using the successor's plan
  (`node.rs:2953-3025`). If the lagging peer is that successor's delegator or
  coding coordinator, it can send an abort to a holder that activated the
  successor but has not installed its Add; that abort deletes READY parity
  (`node.rs:7274-7345`, `network/p2p.rs:6128-6130`). Preserve event-bound
  historical evidence and cleanup lineage. Regress a lagging peer across old
  Add, Forget, and same-ID re-Add while successor Add dissemination is delayed,
  including holder cleanup and reopen.
  Implemented in `366e9e5`: Add atomically stores event-keyed evidence, tail
  catch-up requests that exact event's transcript, and Forget reads the
  original Add binding. Historical replay cannot overwrite a successor's
  current group key. Focused same-ID catch-up and CDDL/transport regressions
  passed locally. An ambiguous pre-binding forgotten Add fails closed; the
  current retained Add can use its durable group-key transcript.

- [x] **M5-141 / P1 — Pin information on remote holders between activation
  and Add.** A remote information holder without a local coding job persists
  the activated transcript but has no launch/activation/retry job
  (`network/p2p.rs:7983-7993`, `node.rs:7154-7162`, `:9481-9524`). If neither
  its current checkpoint nor a retained group names sector S, an existing
  `gc-variable-sector` candidate can mature at the next checkpoint while
  successor Add is delayed; collection
  removes the READY object and receipt (`node.rs:9858-9878`, `:9921-9942`).
  Add can subsequently install without restoring S. Keep a durable holder-side
  pin for a verified pending activation until Add or terminal cleanup. Regress
  a pending reused sector with a matured candidate, delayed Add, source loss,
  and reopen. Current-checkpoint and retained-group references already pin S.
  Implemented in `3419415`: activation writes a holder-local plan pin before
  making shards READY, and Add or terminal discard removes it. A remote-holder
  regression passed with an existing mature GC candidate, unrelated checkpoint
  advance, delayed Add, source-unavailable shard read, and repeated reopen.

- [x] **M5-142 / P2 — Finish repaired-parity receipts after partial cleanup.**
  Repair can leave old volume A in `volume-copy-cleanup` while its READY copy
  and repair attempt receipt are on B (`volume.rs:1318-1361`,
  `node.rs:8031-8066`).
  Old-group cleanup removes B's row, but finalizes the discovered repair
  attempt only after all volumes complete (`volume.rs:680-734`). If A is
  offline, or cleanup stops after `GarbageObjectRemoved`, retry no longer sees
  B's row and does not rediscover the repair ID; the receipt remains after the
  cleanup obligation completes. Reconcile does not process attempt receipts
  (`volume.rs:1481-1525`). Persist receipt-cleanup progress across partial
  passes, and regress offline/restore plus interruption and repeated reopen.
  Implemented in `123d5af`: a durable retirement record is written before
  object removal and replay finalizes that object's attempt receipt even while
  another volume is offline. The offline/restore and injected interruption
  regression passed locally through repeated reopen.

- [x] **M5-143 / gate — Recheck Milestone 5 after M5-139 through M5-142.**
  Review the corrected receipt, event-replay, information-GC, and repair paths
  with focused regressions. Then run the complete local exact-source workspace,
  Docker safety, fresh disposable Btrfs/network acceptance, and independent
  resource-cleanup gate before closing Milestone 5. Passed on clean committed
  code `8f60298a74b74fbef8b92b4eb6a00a92385e7a37`. Focused M5-139 through
  M5-142, historical catch-up, CDDL/transport and dynamic recovery regressions
  passed. Formatting, strict locked all-target workspace Clippy, Docker lab
  safety, and the complete locked all-target workspace tests passed locally
  (node suite: 297 passed, 11 expected ignored). A fresh disposable local
  8 GiB Btrfs image passed all 24 `reflink-acceptance.sh` invocations,
  including full-width QUIC backup (84.07s), repeated multi-owner QUIC backup
  (592.91s), and five-daemon seed/DHT recovery over direct, hole-punched and
  relay paths (1857.15s). The immediate resource snapshot differed only in
  changing IPv4 iptables timestamps and packet counters; a separate normalized
  audit confirmed the owned image, mount, loop, namespaces, links, daemons and
  firewall rules gone, with forwarding and all other snapshots identical.
  Logs: `/tmp/mutualbackup-m5-143-workspace.log`,
  `/tmp/mutualbackup-m5-143-clippy.log`,
  `/tmp/mutualbackup-m5-143-docker-safety.log`,
  `/tmp/mutualbackup-m5-143-provisioned.log`, and
  `/tmp/mutualbackup-m5-143-independent-audit.log`. All compilation and
  execution were local; no remote compilation server was used. Milestone 5
  was closed at that point. This source-only review of `6606cc1` found
  M5-144 through M5-148 below and reopened it. M5-143 and M5-137 remain
  historical passing evidence for their exact tested sources.

- [x] **M5-144 / P1 — Keep variable-profile shards accessible during volume drain.**
  The public drain/migrate path reaches `StorageVolumes::migrate_draining`
  without a variable-shard guard (`node.rs:2112-2120`). Its only drain
  iterator, `ParityStore::first_ready_object`, selects `format_version = 1`
  (`database.rs:1755-1771`; `volume.rs:1735-1742`). A volume containing only
  READY format-2 information or parity therefore reports zero moved objects;
  retirement deletes its active receipts and closes the store while those
  shards remain on it (`volume.rs:1798-1804`, `:1915-1938`). Subsequent
  variable reads require that missing receipt (`volume.rs:1405-1427`), and the
  volume is reported safe to remove. Include format-2 objects in a durable
  cross-volume migration or refuse retirement while any remain. The correction
  chooses safe refusal: after migrating any format-1 objects, drain will not
  retire a source while format-2 objects or coding reservations remain. Its
  receipt and readable source stay durable until ordinary cleanup removes the
  shard. A two-volume format-2 READY regression confirms repeated migration
  attempts and reopen retain the receipt and readable object, then allows
  retirement after terminal cleanup. The volume and store suites pass locally.

- [x] **M5-145 / P1 — Preserve forgotten-Add evidence during seed recovery.**
  Cold dynamic recovery fetches transcripts only for currently retained
  groups (`network/p2p.rs:10080-10097`). Adoption stores all historical guild
  events but writes `coding-event-transcript` only for those retained groups
  (`node.rs:2581-2600`, `:2631-2670`). A seed-recovered peer can consequently
  serve an Add/Retire/Forget event tail but cannot serve the transcript for the
  forgotten Add; event-tail sync requires that evidence before advancing
  (`network/p2p.rs:9047-9065`, `:9122-9162`). If it is the only available
  source, an honest lagging member remains stuck before that Add and all later
  events. Recover and validate historical Add bindings needed for tail service,
  or provide another sound replay path. Regress a cold-recovered sole source
  and a lagging member crossing a forgotten Add and later events. Recovery now
  fetches event-bound transcripts for every historical Add and adoption checks
  each against its Add and signing-epoch authority, storing all event bindings
  while retaining current group and attempt indexes only for live groups. A
  recovered-node regression passes through Add/Retire/Forget replay by a
  lagging member after reopen; the existing dynamic adoption test and strict
  all-target `mb-node` Clippy pass locally.

- [x] **M5-146 / P1 — Backfill a legacy retained Add binding before Forget.**
  A pre-M5-140 store has a retained group transcript but no event-keyed
  transcript. The new lookup can use that group-key record while the Add is
  retained (`node.rs:12282-12299`), and Forget loads it successfully
  (`node.rs:3008-3036`). Forget then commits the new state and cleanup without
  persisting the old Add's event-keyed binding (`node.rs:3043-3092`). Once the
  group is forgotten, the fallback rejects the same Add even before a same-ID
  successor arrives, blocking lagging event-tail catch-up. Atomically preserve
  the unambiguous original binding during Forget; regress upgrade from a
  pre-binding retained Add, Forget, same-ID re-Add and lagging catch-up.
  Implemented by writing the original Add's verified transcript atomically
  with Forget and its cleanup obligations. The existing three- and five-domain
  same-ID catch-up regressions now simulate a pre-binding store, check the
  original binding before and after Forget and reopen, and pass locally with
  formatting and strict all-target `mb-node` Clippy.

- [x] **M5-147 / P1 — Certify the Add event's exact verifier attempt.**
  `AddCodingGroup` signs only the group (`guild.rs:135-137`), and the group ID
  excludes attempt identity (`model.rs:278-296`, `:420-433`). A later same-ID
  attempt can have another replay-valid transcript. Event-tail catch-up takes
  the first peer response whose transcript verifies and names that group
  (`network/p2p.rs:2052-2083`, `:9122-9162`), while installation checks only
  replay and group equality (`node.rs:3136-3150`). A guild peer can return the
  successor transcript for an earlier certified Add; the lagging node accepts
  the wrong lineage and its earlier Forget can abort successor shards. A
  source-local event-keyed record does not prove this binding to the receiver.
  Commit the transcript or attempt hash in certified Add authority and verify
  it on catch-up, recovery and Forget. Regress a replay-valid wrong-attempt
  response preceding the correct source. Implemented with an appended
  `AddCodingGroupBound` event variant (format 2) that signs the canonical
  verifier transcript hash. New Add proposals require it; installation,
  event-tail catch-up, seed-recovery fetch/adoption, event evidence service,
  activation lock matching and Forget compare the exact evidence. A same-ID,
  different-attempt regression rejects the wrong transcript without advancing
  state and then installs the correct one; recovery rejects the wrong evidence.
  The appended variant preserves historical Postcard event bytes and old
  format-1 Adds remain readable. A byte-level legacy decode/encode regression
  covers that compatibility. Strict workspace Clippy passes locally. Historical
  format-1 Adds still have no signed hash; M5-150 tracks that residual gap.

- [x] **M5-148 / P2 — Clear orphan pending activation pins.**
  Activation contacts every information owner, including virtual-zero-only
  owners (`network/p2p.rs:8006-8025`), and writes their durable
  `coding-pending-activation` record before recognizing the zero role
  (`node.rs:7284-7311`). If membership or placement changes before Add, stale
  activation cleanup runs, but its abort holder set excludes virtual-zero
  owners (`network/p2p.rs:6505-6549`, `:7830-7837`). No Add or abort then
  removes their records, which accumulate and keep every nonzero sector ID in
  each abandoned plan in the GC live set (`node.rs:9646-9651`). The method
  also writes a pin before checking for any local role, so an activation sent
  to a non-holder returns an error but leaves a record (`node.rs:7382-7384`).
  Include every activated holder in terminal cleanup and validate the local
  role before persisting a pin. Regress stale abort, checkpoint GC and repeated
  reopen for a virtual-zero-only owner, plus rejected non-holder activation.
  This review ran no builds, tests, daemons or runtime probes; M5-143's
  passing gate remains evidence for its exercised cases. Implemented in the
  next correction: activation now checks local assignment before any pin write
  and writes a pin only for a physical local shard. GC retires legacy pins
  whose plans give this node no physical shard. The zero-only/non-holder and
  existing remote-information retention regressions pass through reopen;
  formatting and strict all-target `mb-node` Clippy pass locally.

- [x] **M5-149 / P1 — Revalidate the corrected milestone on exact source.**
  Run formatting, strict workspace Clippy, locked all-target workspace tests,
  Docker safety and the fresh disposable Btrfs/network acceptance matrix on
  one committed source. Independently audit cleanup of owned mounts, loop
  devices, namespaces, links, daemons and firewall rules. Record the exact
  source and local logs after M5-150 is resolved, before closing Milestone 5.
  The first all-target workspace run passed the new legacy-wire and
  wrong-attempt regressions but one unrelated long network test hit the
  shell's 1,024-descriptor limit; that test passed alone with the established
  8,192-descriptor limit. Docker safety, formatting and strict workspace
  Clippy passed locally. This is not yet an exact-source milestone gate.
  A later four-thread workspace run on `f277419` passed 302 `mb-node` tests
  but repeated a directory-lock race in the five-domain activation test's
  immediate reopen; the same test passed alone. That fixture now waits up to
  30 seconds for already-running blocking workers to release their final node
  handle, matching the existing inbound-worker reopen pattern. Its focused
  rerun and strict workspace Clippy passed. On committed source
  `04c6d7a0e671338be469132876ce2cabf86a7db2`, formatting, strict
  workspace Clippy, locked all-target workspace tests (including 303 passing
  `mb-node` tests) and Docker safety passed. The fresh disposable Btrfs matrix
  passed every case before the five-daemon network smoke test, including
  five-node seed recovery and both QUIC backup cases. That smoke test timed
  out after 5,400 seconds waiting for the first isolated-topology backup to
  commit (M5-152), so this exact-source gate did not pass. The gate script and
  independent audit confirmed that its image, mount, loop device, namespaces,
  links, daemons and firewall rules were removed and normalized host-resource
  snapshots matched. Local logs: `/tmp/mutualbackup-m5-149-core-gate.log`,
  `/tmp/mutualbackup-m5-149-provisioned.log`, and
  `/tmp/mutualbackup-m5-149-cleanup-audit.log`. A subsequent exact-source
  workspace rerun on `fef9a25` exposed a separate immediate-reopen race in
  the three-domain activation fixture after 302 `mb-node` tests passed;
  M5-153 corrects that fixture. The final complete gate passed on committed
  source `0c3924457ada6bc3b308a6cdcaeebdf8a83eec21`: formatting,
  warning-free strict workspace Clippy, locked all-target workspace tests
  (303 passing `mb-node` tests), Docker safety, all 24 provisioned acceptance
  invocations including the five-daemon process scenario, and independent
  cleanup of the image, mount, loop, namespaces, links, daemons and firewall.
  The complete-gate logs are `/tmp/mutualbackup-m5-152-final-core-gate.log`,
  `/tmp/mutualbackup-m5-152-full-provisioned.log`, and
  `/tmp/mutualbackup-m5-152-full-cleanup-audit.log`. At that point M5-152
  remained open because the earlier 5,400-second topology timeout was not
  explained by the passing rerun.

- [x] **M5-150 / P1 — Authenticate historical unbound Add evidence on catch-up.**
  Format-1 `AddCodingGroup` must remain decodable for existing guild history,
  but it signs only the group. `coding_group_add` returns no transcript hash
  for it; event installation, event evidence service and recovery check an
  expected hash only when present. A malicious peer can still supply a valid
  same-ID successor transcript for a historical Add, and the lagging member
  will accept that attempt before replaying Forget. This is precisely the
  upgraded pre-binding history exercised by M5-146, so the new format-2 Add
  does not secure all supported history. Define and enforce a trusted
  re-binding path for old Adds (or explicitly fail closed with an agreed
  migration policy) before calling their catch-up and seed recovery safe.
  The selected migration policy rejects every format-1 Add during ordinary
  event-tail catch-up, before requesting verifier evidence; the public node
  installation path also rejects it. Existing installed history remains
  readable for local lifecycle work. Background migration may issue a durable
  quorum certificate while original signers and evidence still exist. Cold
  recovery accepts a legacy Add only with an already issued certificate and
  exact matching transcript; it does not solicit fresh signatures during
  recovery. Without that certificate, it fails closed and requires trusted
  assisted recovery. Focused rejection, wrong-attempt, certificate-adoption
  and reopen regressions pass locally; M5-149 remains the closure gate.

- [x] **M5-151 / P1 — Define the fail-closed migration policy for historical Adds.**
  Source-only review of the in-progress M5-150 correction found that a legacy
  binding requires the event-time quorum of original Add signers
  (`crates/mb-core/src/guild.rs:270-306`; `network/p2p.rs:9111-9140`). Cold
  recovery removes the recovering subject from every witness source
  (`network/p2p.rs:10230-10239`), even if that subject signed the old Add.
  For a five-member unanimous Add, at most four witnesses remain, so the
  early quorum check always fails; an empty-directory seed recovery containing
  any such Add cannot complete. Event-tail catch-up similarly excludes the
  lagging member (`network/p2p.rs:9024-9037`), and later membership removal
  can make the original quorum unavailable even when all current peers are
  healthy. Define an explicit, authenticated migration or fail-closed policy
  for these histories that preserves the seed-only recovery invariant where
  promised. Regress a historical unanimous Add through empty-directory
  recovery and lagging catch-up, including original-signer loss and membership
  change, before closing M5-150. This review ran no builds, tests, daemons or
  runtime probes; M5-149 remains pending on the final committed source.
  The agreed policy is to reject legacy event-tail catch-up entirely and fail
  closed on seed recovery unless an existing quorum certificate can be
  obtained. A node with the old history proactively creates and replicates up
  to 16 certificates per peer-exchange pass while original signers remain.
  Recovery never asks the lost subject to attest; a certificate already held
  by a surviving peer is sufficient, including after signer loss or membership
  change. If no certificate exists, trusted assisted recovery is required:
  automatic seed-only recovery is intentionally unavailable for that
  pre-migration legacy history. Focused tests cover unanimous certificate
  construction, rejection of ordinary catch-up, rejection of certificate-free
  recovery, exact-attempt adoption, and reopen. The complete local P2P and
  provisioned gate remains M5-149.

- [x] **M5-152 / P1 — Resolve isolated-topology backup timeout in the exact-source gate.**
  The fresh local M5-149 acceptance matrix on `04c6d7a` passed all earlier
  provisioned cases, then `five_daemons_recover_latest_snapshot_from_seed_and_dht`
  timed out at `prototype_acceptance.rs:1598` waiting for its first
  isolated-topology `backup --wait` after 5,400 seconds. The owner still had
  one checkpoint and a dirty root; direct and relay-fallback transfer counters
  kept rising, so the process was live but did not commit. Diagnose the durable
  backup/coding state and topology path with retained daemon logs on a fresh
  disposable run, correct any source failure, and rerun the full M5-149 gate
  on one committed source. Do not treat the passing workspace and earlier
  provisioned cases as milestone closure. Two fresh smoke-only runs on the
  unchanged production code subsequently passed in 1,644 and 1,972 seconds,
  including both isolated-topology backups and independent cleanup audits.
  Their coordinator records showed coding jobs, activation, event signatures
  and checkpoint generations advancing. This makes the original timeout
  intermittent. A later complete Btrfs/network gate on `0c39244` also passed,
  including both topology backups after the preceding provisioned cases on
  the same image. The full gate is recorded under M5-149. Keep this reliability
  blocker open until the 5,400-second outlier has a diagnosed cause or a
  source-level correction; one successful rerun alone does not explain it.
  The acceptance fixture now waits up to 45 seconds for the coordinator to
  show a live connection to the fallback signer before starting the first
  isolated-topology backup. This closes a readiness gap in the test and makes
  a missing circuit fail at the topology boundary; it does not yet diagnose
  the original timeout. A fresh local smoke run on `4ba4d63` reached that
  check and entered the first isolated backup with all five peers connected,
  then made no durable coding/event progress for more than 20 minutes. The
  diagnostic run was stopped and its daemons, namespaces, firewall, mount and
  image cleaned up. Read-only control DB copies showed three verified but
  incomplete activations, a locked Add at sequence 32, and the same signed
  event hash locked on all five peers. A live debugger sample found the coding
  worker repeatedly replaying the full signed guild history inside
  `claim_coding_activation` while other workers waited on the node mutex.
  Membership-history snapshots are now cached by the durable guild state so
  authority checks replay the event chain once per state change and again
  after reopen. The focused cache/reopen regression, formatting, strict
  workspace Clippy, and locked all-target workspace tests pass locally; the
  latter ran with the acceptance harness's 8,192-descriptor limit. A fresh
  five-daemon provisioned smoke run on `e44a220` passed both topology backups
  and recovery in 1,206.63 seconds, with its disposable resources cleaned up.
  The final exact-source gate passed on committed source `53ec2ec`: formatting,
  strict locked all-target workspace Clippy, the locked all-target workspace
  suite (304 passing `mb-node` tests), Docker safety, all 24 fresh provisioned
  cases, and an independent cleanup audit. The five-daemon case passed both
  topology backups and seed/DHT recovery in 1,201.82 seconds after the other
  23 provisioned cases on the same image. Logs are
  `/tmp/mutualbackup-m5-152-cache-workspace-rerun.log`,
  `/tmp/mutualbackup-m5-152-cache-full-provisioned.log`, and
  `/tmp/mutualbackup-m5-152-cache-full-cleanup-audit.log`; separate Docker
  safety and independent audit logs are
  `/tmp/mutualbackup-m5-152-cache-docker-safety.log` and
  `/tmp/mutualbackup-m5-152-cache-full-independent-audit.log`. The independent
  audit verified absence of the owned image, mount, loop, namespaces, links,
  daemons and firewall rules, and identical normalized host-resource snapshots.
  Milestone 5 is closed; Milestone 6 may proceed.

- [x] **M5-153 / P2 — Wait for aborted coding workers in the activation reopen fixture.**
  The all-target workspace rerun on `fef9a25` passed 302 `mb-node` tests but
  `retired_three_domain_activation_worker_forgets_and_reopens` reopened the
  node directory immediately after aborting async coding workers and hit the
  same transient lock race previously corrected in the related fixture.
  Its final reopen now uses a bounded wait while an already running blocking
  worker releases its node handle. The focused three-domain regression,
  formatting and strict workspace Clippy pass; both three- and five-domain
  fixtures also pass in M5-149's complete concurrent suite.

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
