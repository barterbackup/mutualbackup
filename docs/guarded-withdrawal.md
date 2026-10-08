# Guarded backend withdrawal

The FUSE-backed guarded backend is withdrawn. New guarded enrollment commands
are no longer exposed. Old local control requests receive a withdrawal error.
The daemon inspects existing control catalogs read-only before key wrapping,
schema migration, journal replay, or mount recovery. Guarded journals, root
bindings, and pending guarded capture or recovered-anchor intents cause startup
to stop. The read-only check also opens registered Git catalogs when their source
is present and rejects guarded bindings, journals, and root-backed historical
blobs. Historical single-file captures can have ordinary format-1 manifests;
their guarded ownership markers also stop admission when the anchor area is
available, even if the catalog claims a native binding. Root and mount records
need not remain for that detection to work. An unbound catalog must have
available anchor provenance before migration. A native binding must be stored
under the repository's own key. A bound native catalog may retain unavailable
or damaged copies for repair; that does not certify legacy export.
Locally available authenticated revision metadata in user revisions, revision
heads, and certified checkpoint history identifies withdrawn formats 6 and 7;
the first metadata sector suffices even when later sectors are absent.
Source-loss recovery cannot enroll a guarded revision as a new root.
Decoded legacy capture plans cannot capture, replay, detach edits, or discard
anchors through the versioned source-backend API.

The mount runtime, supervisor, capture/publication paths, guarded Git operations,
link-freeze machinery, and `fuser` dependency have been removed. Minimal historical
record decoding and marker recognition remain for rejection and preservation.
Ordinary and linked-worktree stage journals are inspected even when their backend
binding is absent; neither initialization nor reopening can migrate them first.
Automatic migration remains disabled. The Linux `legacy-export` command can
export an owner/writer-signed historical revision from available ciphertext
files or a read-only original control catalog without mounting a guarded view.
Offline Git catalogs and revision metadata not yet downloaded during seed
recovery cannot be classified by the startup check. Recovery admission must
classify the downloaded metadata before publishing a restore job or enrolling
its root. The complete recovery/export policy remains tracked in R1.
Do not interpret a successfully opened native catalog as proof that all retained
history has been converted.

## If startup reports withdrawn guarded state

1. Preserve the recovery string and the complete original installation: data
   directory, control key envelope, every parity volume, source and lower trees,
   Git catalogs, and all external anchor areas. Database copies must include any
   WAL files from an interrupted process. Keep a consistent filesystem image or
   backup of these together, including native permissions, ownership, ACLs,
   sparse extents, and hard links. Copying just the visible working tree does
   not preserve retained history or staged differences.
2. Leave the original state intact. Do not delete guarded records, change backend
   identifiers, run enrollment/removal against these paths, or clean up anchor
   directories to bypass the error. Startup rejection does not authorize
   unmounting or deleting an existing view. A previous binary is not a qualified
   migration tool: the withdrawn capture path has unresolved isolation defects.
3. If continuing with native capture, create a separate data directory and
   source tree on a qualified filesystem. Enroll that tree using `root add`.
   Preserve the original identity and peer-held recovery data until replacement
   files, exact Git objects/refs, and retained revisions have been independently
   verified and durably protected. Native enrollment of a copied working tree
   alone does not establish that replacement.
4. Export available authenticated revisions with the procedure below. Keep all
   unavailable revisions, original catalogs, anchors, keys and peer recovery
   data. Exporting one revision does not certify conversion of every retained
   revision or safe retirement of the original installation. Full upgrade and
   seed-recovery qualification remains tracked in R1 of [TODO.md](../TODO.md).

Fresh native installations continue to use reflink capture. Unsupported source
filesystems are rejected; withdrawal does not introduce a copy or mount fallback.


## Offline export of available signed revisions (Linux)

Provide an owner/writer-signed `SignedRecord<UserRevision>` in canonical Postcard
encoding and every metadata/data ciphertext sector it references. Each ciphertext
file must be exactly 64 KiB and named `<sector-id-hex>.bin`. These inputs must come
from preserved authenticated recovery/export data. The file-input mode accepts previously extracted inputs. The catalog-input mode
below reads available recovered inputs from the preserved encrypted installation.
Catalog mode can use the explicitly selected peers described below; complete
retained-history recovery and conversion remain required for the R1 procedure.

Create the destination's parent outside the revision and ciphertext input
directories, then run:

```sh
mutualbackup legacy-export \
  --revision-file /preserved/inputs/revision.postcard \
  --sectors-dir /preserved/inputs/ciphertexts \
  --destination /exports/revision-001 \
  --seed-file /preserved/recovery.txt
```

To find revision IDs already available in a preserved installation, run:

```sh
mutualbackup legacy-list \
  --data-dir /preserved/installation \
  --seed-file /preserved/recovery.txt
```

The JSON report lists this identity's owner/writer-signed revisions from saved
revision rows, recovery heads and quorum-certified local checkpoints. Matching
records are deduplicated and show which metadata sources contain them. It reads
existing encrypted control data without daemon startup, key wrapping, migration,
journal replay or opening original anchors. Missing ciphertext does not prevent
metadata inventory. Invalid signatures, conflicting record IDs/scopes or two
different signed records with one revision ID fail without a partial report.

To include missing local revision metadata from explicitly selected survivors:

```sh
mutualbackup legacy-list \
  --data-dir /preserved/installation \
  --peer NODE-ID=MULTIADDR \
  --seed-file /preserved/recovery.txt
```

Repeat `--peer` to combine survivors. The preserved quorum-signed
guild genesis certificate is required to bind the guild and origin. Peer heads
and every parent are checked for canonical encoding, page/full hashes, quorum,
exact preceding generation and guild/genesis. Later-member authorization replays
signed membership evidence as for export, including removed-member history.
The report deduplicates available local/remote signed records and marks
`peer_checkpoint` provenance. Conflicting records fail without a partial report.

`peer_coverage` records selected peer identities, verified checkpoint visits
(including repeated copies), unavailable heads/parent links and certificates
whose owner membership authority could not be established. These gaps must be
resolved before declaring a complete retained-history inventory. Traversal keeps
one checkpoint plus bounded head cursors, caps visits at the existing one-million
recovery work bound, and uses a private temporary client outside the original
installation. It issues only authenticated reads and installs no peer evidence,
replay state or keys in the original catalog. Bootstrap directory contacts remain explicitly selected.

If survivor addresses are unknown, select a production Kademlia bootstrap endpoint:

```sh
mutualbackup legacy-list \
  --data-dir /preserved/installation \
  --bootstrap-peer NODE-ID=MULTIADDR \
  --seed-file /preserved/recovery.txt
```

`legacy-export` accepts the same repeatable `--bootstrap-peer` in catalog mode;
combine it with `--revision-id` and `--destination`. Explicit `--peer` survivors
may be combined with bootstrap endpoints. Bootstrap identities are directory
contacts, not automatically authorized survivors. Discovery queries this owner's
recovery mailbox and live signed/encrypted recovery bundles using the production
Kademlia protocol. It checks provider identity, subject/guild, signatures, expiry,
endpoint identity and same-sequence equivocation before learning routes. Original
and seed-wrapped rotated recovery keys can open routing locators. A locator grants
no membership, current-key, enrollment, shard or checkpoint authority: subsequent
signed checkpoint and membership checks remain mandatory.

Discovery has a 60-second deadline, up to four bundle lookups in flight, existing
64-provider/64-record query bounds, a 64 KiB encoded bundle-record limit and at
most 64 selected survivor identities. It creates no directory publication, recovery
attempt, durable observation or original-state update. Preserved signed genesis
is required before directory discovery. Temporary client placement is checked
before creating client state. Missing or invalid directory evidence fails discovery;
keep the explicit-peer fallback and preserve all source/history inputs. The real
fixture below exercises direct QUIC; relay/Tor discovery qualification remains
part of the full release gates.

Report format 9 includes preserved local protected-root registrations, backend
bindings, Git registrations, guarded stopped/revision-capture anchor ownership,
pending source-capture and recovery-anchor intents, pending Git graph intents,
retained revision/retirement anchors and remembered anchor-area locations.
Capture envelopes 1/2/3 and recovery envelopes 1/2 are checked against their
original canonical layouts; inventory never migrates or replays them. Pending
ownership includes the planned root anchor and guarded per-file capture IDs,
plus any anchor retained during
recovery replacement. Relative historical requests are reported as bytes without
resolving them against the inventory process's working directory.
Raw Unix paths are reported as hex bytes. Local control records and signed
revisions come from one read-only SQLite snapshot, released before peer requests.
Available external Git catalogs use their own non-creating metadata snapshots;
these do not establish an atomic snapshot of every owner across filesystems.
The complete canonical encoded report has a 32 MiB metadata limit; exceeding it fails the
inventory instead of returning a truncated success. Binding identity comparisons
are unknown for missing roots and older registration formats 1/2. Git registrations
can be history-only: `catalog_inventoried` remains false because complete external
refs, objects, pins, index and pending-intent reconciliation is unfinished.
Unknown guarded/link-freeze control records are listed with their
kind, ID, payload size and digest for preservation; they are not decoded ownership.
Git graph intent envelopes 1/2 retain their original bytes. libgit2 validates
object IDs, reachable commit/tree/tag history, refs and declared blob lengths
using a repository backed only by an in-memory object database. No Git catalog,
config file or temporary repository is created; blob payloads are not opened.
The report identifies refs (including pins), metadata objects, native/imported
blob manifests and guarded virtual mappings with their physical root-anchor
locations. Envelope 1 omitted the selected branch: its decoder default `main`
is reported with `head_branch_recorded: false`, not as a recorded selection.
Same-revision/guild/root signed metadata availability does not authenticate the
pending graph or establish that its blob payloads survive.

The `git_object_anchors`, `git_indexes` and `git_anchor_area_locations` entries
preserve original external object mappings, primary/linked staged ownership and
cached area locations. These and linked worktrees come from one non-creating
external snapshot per repository. Original native, withdrawn root-backed and
imported file manifests keep physical locator and recorded/stable identity
provenance through the existing decoder and `preserved_ownership` checks.
Index scope, raw path, OID, mode and anchor ID remain visible even if a linked
registration is absent. Relative cached locations are reported without resolving
against the current cwd. Canonical/key/namespace/shape validation shares the
existing object-row limit (32 MiB), bounded index rows (512 bytes) and paths
(4,096 bytes), and the original cached-location row/path limits (4,112/4,096
bytes). The complete report still has one 32 MiB encoded limit. Known source,
area and absolute cached-location hints and aliases exclude output/scratch
parents. No source/anchor payload or working marker is opened, and no Git work
is replayed. `object_anchors_inventoried`, `worktree_indexes_inventoried` and
`anchor_area_locations_inventoried` describe these families, while full
`catalog_inventoried`, payload verification and history completeness remain
false. Original-wire closed/WAL-only/live, raw-path/relative-hint/JSON,
malformed-record, report-budget, late-corruption and actual CLI ownership/
placement fixtures cover unchanged original catalogs and working files.
External Git anchor/index qualification passes 242 unique cases: 47
export/peer cases, all 63 ordinary volume and 105 ordinary Git cases, 20 CLI
process cases, retained-graph/discovery/withdrawal/graph-intent regressions,
and two provisioned Btrfs identity/retained-capture cases. All four debug
programs build; format and strict locked workspace/all-targets Clippy pass.
All 284 source-file and seven program/test-driver hashes remain unchanged, and
native mount/loop/image cleanup is verified. Evidence and the distinct
passing-case inventory are retained under
`/tmp/mb-m6-external-git-owners-validation-is_jr74i`; the post-commit audit
binds the code to the commit. This is a focused debug-source qualification;
complete ordinary/native suites and installed artifacts were not rerun. Full refs/non-blob
objects/pins, stage/prune/checkout/merge/removal-intent joins, relocated owner
discovery and atomic admission/writer handoff remain open.

The `git_worktrees` entries inspect original linked-worktree registrations through
the per-repository key, pinned private catalog and repository marker. Preparing,
Ready and Removing records retain saved paths, root identities and target
branches without selected-HEAD repair or source/removal replay. Missing roots
or catalogs leave availability/coverage false. An available validated catalog
sets `external_catalog_available` and `linked_worktrees_inventoried`; this does
not make `catalog_inventoried` true. Inventory and placement share canonical,
key, namespace and shape validation, the existing 256-worktree limit and bounded
SQL rows. Absolute paths/aliases and both interpretations of recorded native
identities exclude destinations, including renamed worktrees. Recorded identity
words are not evidence of their stable-identity era. Every report entry shares
the complete 32 MiB encoded-report budget. No working files or worktree markers
are opened, and payload verification/history completeness remain false.
The actual CLI fixture inventories an original Preparing record and rejects
worktree/alias export and scratch parents while preserving both catalogs and
working files. External Git worktree qualification passes 240 unique cases: 46 export/peer
cases, all 63 ordinary volume and 104 ordinary Git cases, 20 CLI process
cases, retained-graph/discovery/withdrawal/graph-intent regressions, and two
provisioned Btrfs identity/retained-capture cases. All four debug programs
build; format and strict locked workspace/all-targets Clippy pass. All 284
source-file and seven program/test-driver hashes remain unchanged, and native
mount/loop/image cleanup is verified. Evidence and the distinct passing-case
inventory are retained under `/tmp/mb-m6-git-worktree-validation-xaclttn_`;
the post-commit audit binds the code to the commit. This is a focused
debug-source qualification; complete ordinary/native suites and installed
artifacts were not rerun. Complete refs/objects/
pins/index/stage/prune/checkout/merge/removal-intent reconciliation, other owner
joins, relocated catalog discovery and atomic admission/writer handoff remain open.

Retained `anchor-manifest` versions 1/2/3 and stable `anchor-retirement` records
are validated without replay. Revision-keyed manifests can link available signed
metadata; retirement keys identify anchors and are never inferred to be revision
IDs. Version 1 lacks a filesystem/volume locator, so its corresponding report
fields are null. Imported stream manifests can lack a native file identity;
ordinary native file identity words remain ambiguous, while guarded root-backed
file identities postdate stable filesystem IDs. File identities are not treated
as directory roots during placement checks. Remembered area paths retain raw
bytes and their absolute/relative status. Absolute cache hints participate in
placement; relative historical hints do not inherit the current process cwd.
These hints are not verified area ownership or evidence of complete relocation
discovery.

Peer-client and export placement also inspect the saved storage-volume registry,
including volumes not selected for recovery and retired or unconfigured entries.
Current and historical pre-configured-state records preserve raw path bytes. The
reader shares paged scratch admission's existing 4 MiB/1,023-record bounds and
validates the complete bounded registry before using locations. Invalid or
relative paths, escaping database names and duplicate volume IDs reject before
client/output creation. It opens no volume manifests or payloads and publishes
no key, registry, receipt or recovery state. Registered volume descendants and
symlink aliases are excluded; missing absolute hints remain unavailable locations,
not evidence of relocated ownership. Saved-volume placement qualification passes 159 unique cases: 39 export/peer
cases, all 61 ordinary volume cases, all 32 ordinary paged cases, 20 CLI
process cases, retained-graph/discovery/withdrawal/graph-intent regressions,
and two provisioned Btrfs identity/retained-capture cases. All four debug
programs build; format and strict locked workspace/all-targets Clippy pass.
All 284 source-file and six program/test-driver hashes remain unchanged, and
native mount/loop/image cleanup is verified. Evidence and the distinct
passing-case inventory are retained under
`/tmp/mb-m6-volume-placement-validation-kowi9nmv`; the post-commit audit binds
the code to the commit. This is a focused debug-source qualification; complete
ordinary/native suites and installed artifacts were not rerun. Full receipt/recipe/pin/intent reconciliation, renamed volume discovery,
mount-descendant aliases and atomic path/ownership handoff remain open. Volume
registrations are inventoried below; complete volume-owner reconciliation and
history completeness remain open.

The `storage_volumes` entries report saved volume IDs, raw paths, database names,
states, configured status and budget/headroom from that same snapshot. Wrapped
keys are omitted. Historical records defaulted to `configured: true` without
storing the field; `configured_recorded: false` preserves that distinction.
Unconfigured and retired registrations remain included. Their locations and
geometry do not verify payload custody: `payloads_verified` and
`retained_history_complete` remain false. Each entry contributes to the complete
32 MiB encoded-report budget; excess metadata rejects without a partial report.
Storage-volume inventory qualification passes 128 unique cases: 40 export/peer
cases, all 61 ordinary volume cases, 20 CLI process cases,
retained-graph/discovery/withdrawal/graph-intent regressions, and two
provisioned Btrfs identity/retained-capture cases. All four debug programs
build; format and strict locked workspace/all-targets Clippy pass. All 284
source-file and six program/test-driver hashes remain unchanged, and native
mount/loop/image cleanup is verified. Evidence and the distinct passing-case
inventory are retained under
`/tmp/mb-m6-volume-inventory-validation-gdx0ells`; the post-commit audit binds
the code to the commit. This is a focused debug-source qualification; complete
ordinary/native suites and installed artifacts were not rerun. Complete receipt,
recipe, local-sector, native-pin and pending-intent reconciliation, external
Git catalogs and relocated volume discovery remain open.

The `volume_ownership` entries decode saved receipt, write-intent, staged-attempt,
reservation, retirement, variable-migration and copy-cleanup records using the
original layouts. Record keys, sizes and hashes accompany the ownership and
attempt/commitment/cleanup metadata. `unregistered_volume_ids` identifies references
without a saved registry entry; it does not assert that a volume or its data is
missing. Inventory and placement share canonical/shape/key validation and SQL row
bounds: 512 bytes for fixed-size records and the existing 32 MiB local-row bound
for historical cleanup UUID lists. Every report entry also contributes to the
complete 32 MiB encoded-report budget. Corrupt late records reject before client
or output creation. No volume is opened or pending operation replayed. Metadata
hashes identify preserved records; they do not authenticate READY custody or
resolve conflicting attempts. Payload verification and history completeness
remain false. Volume custody inventory qualification passes 131 unique cases: 41 export/peer
cases, all 63 ordinary volume cases, 20 CLI process cases,
retained-graph/discovery/withdrawal/graph-intent regressions, and two
provisioned Btrfs identity/retained-capture cases. All four debug programs
build; format and strict locked workspace/all-targets Clippy pass. All 284
source-file and six program/test-driver hashes remain unchanged, and native
mount/loop/image cleanup is verified. Evidence and the distinct passing-case
inventory are retained under
`/tmp/mb-m6-volume-ownership-validation-o4_qqllw`; the post-commit audit binds
the code to the commit. This is a focused debug-source qualification; complete
ordinary/native suites and installed artifacts were not rerun. Complete
receipt-to-payload/recipe/local-sector/native-pin joins, external Git catalogs,
relocated volume discovery and atomic admission/writer handoff remain open.

The `local_sectors` entries decode the original unversioned recipes and all four
append-only source variants. They report guild/sector/ciphertext-root identity,
logical length and legacy/stable anchor or private-page metadata. Inline data is
represented by its byte length only, including zero-length synthetic filler.
No inline plaintext, anchor payload or private page is returned or opened. The
shared inventory/placement reader validates canonical encoding, keys, geometry,
relative anchor paths and overflow within the existing 68 KiB SQL row bound.
Absolute recipe-only area hints and aliases exclude client/export locations;
relative historical hints do not acquire the current process cwd. Volume-root
hints remain discovery starting points rather than ownership of a filesystem.
Recorded filesystem words do not establish a stable relocated identity. Each
entry contributes to the complete 32 MiB encoded-report budget, and payload
verification/history completeness remain false. The initial qualification retained under
`/tmp/mb-m6-local-sector-validation-rvsv40wf` exposed a CLI fixture write
after read-only shell inspection. Filler creation now precedes inspection;
recipe production code is unchanged. Local-sector recipe qualification passes 135 unique cases: 45 export/peer
cases, all 63 ordinary volume cases, 20 CLI process cases,
retained-graph/discovery/withdrawal/graph-intent regressions, and two
provisioned Btrfs identity/retained-capture cases. All four debug programs
build; format and strict locked workspace/all-targets Clippy pass. All 284
source-file and six program/test-driver hashes remain unchanged, and native
mount/loop/image cleanup is verified. Evidence and the distinct passing-case
inventory are retained under `/tmp/mb-m6-local-sector-validation-m858b2w1`;
the post-commit audit binds the code to the commit. This is a focused
debug-source qualification; complete ordinary/native suites and installed
artifacts were not rerun. Complete recipe/native-pin/paged-source/custody joins,
external Git catalogs, relocated owner discovery and atomic admission/writer
handoff remain open.

Native root plan format 1 predates stable filesystem IDs, and its wire layout did
not change when the filesystem word changed from `st_dev` to a stable identity.
A newer intent envelope may contain a migrated old plan. Its recorded root/area
identity is therefore reported without asserting a stable root identity. Guarded
root plans were introduced after that change and retain stable identities.
Available signed metadata is linked to pending records only for the same revision
and guild; it does not authenticate a pending plan or verify its payloads.
Source/worktree/anchor payloads and withdrawn mount views are not opened during inventory,
so `payloads_verified` remains false even when signed revision metadata is available.

The pending-intent increment was qualified on Linux on 2026-10-08 with 336
unique passing cases: the full ordinary store suite, inventory/export/peer and
CLI process slices, discovery, withdrawal and separately provisioned native
Btrfs regressions. Closed catalog bytes and file sets, raw Unix pins, malformed
intents, report budget rejection, pending-only moved sources and old native
intent migration are covered. Both disposable Btrfs filesystems, loop devices
and images were removed with cleanup verified. All four debug programs build;
formatting and strict workspace/all-targets Clippy pass. This qualifies the
exercised source slice; other ignored fixtures, installed artifacts and the
complete upgrade/source-loss/platform matrix remain release gates.

The graph/native-owner increment was qualified on Linux on 2026-10-08 with
444 unique passing cases: 282 ordinary store cases, 100 ordinary Git cases,
36 inventory/export/peer cases, two discovery cases, 19 ordinary CLI process
cases, withdrawal and historical graph-intent compatibility, and three
provisioned Btrfs regressions. New fixtures cover graph ancestry, pins and tags,
original manifest layouts, raw blob/area paths, imported and guarded mappings,
malformed metadata, retirement keys and bounded absolute/relative area caches.
Closed catalog bytes and file sets remain unchanged. Inspection and placement
also pass in a child process with a nonexistent TMPDIR, which remains absent.
All four debug programs build; format and strict workspace/all-targets Clippy
pass. The 283 source files and eight program/test drivers retain their hashes
throughout qualification, and disposable mount/loop/image cleanup is verified.
Sixty-four Git, 26 store and three CLI process fixtures remain ignored. These
results qualify the exercised source; installed releases, complete ownership
inventory, retained conversion and the full M6 release gates remain open.

Preserved catalog opens forbid database/journal creation and deletion. A catalog with no
journal files uses an immutable read only while its file identity, size, mtime,
ctime and journal absence remain unchanged; a concurrent change fails the whole
inspection. Existing WAL/SHM pairs use SQLite read snapshots without checkpointing
the original database or WAL; an existing writer's shared mapping may update
transient read marks. A WAL without SHM uses SQLite's private in-memory index,
after checking the WAL header's format, page size and checksum. Both database and
WAL versions and the absence of SHM/rollback journals must remain unchanged until
inspection finishes. SQLite recovers committed frames and ignores an interrupted
transaction tail without writing an index beside the original. Empty WALs are
accepted. Partial or corrupt headers in WAL-only inputs, SHM without WAL and
rollback journals are rejected before SQLite opens them. Preserve all files from that installation and
inspect a separate complete snapshot; never delete or checkpoint its original
journals to make an inspection succeed. These stricter opens apply to `legacy-list`,
placement preflight, Linux Node catalog admission, Git catalog admission and
Git discovery listing. Catalog read operations reuse an enclosing read-only
snapshot without committing or rolling it back, including metadata rendering
during native admission.

The admission/WAL increment was qualified on Linux on 2026-10-08 with 961 unique
passing cases: 474 ordinary Node, 288 store, 102 Git and 19 CLI process tests;
all 64 provisioned Git cases, 11 native Node cases, extent sharing/prune, the
stock-Git bridge and raw Unix CLI/daemon/Git paths. Native checks include
signed-history pruning/reopen and format-7 packed checkpoint retention, obsolete
coding-group retirement and two independent seed-only recoveries. All four debug
programs build; formatting and strict locked workspace/all-targets Clippy pass.
The 284 source files and ten program/test drivers keep their hashes through
qualification. The packed-checkpoint case exceeded an initial 900-second outer
harness cap; its log and failed-attempt evidence remain separate. Unfinished
checks passed on unchanged inputs with a 2,400-second outer cap for that case
and unchanged application phase deadlines. Mount, loop and image cleanup is
verified. Evidence, frozen manifests and the distinct passing-case inventory
are retained under `/tmp/mb-m6-admission-validation-m6aad954`; the post-commit
audit binds the qualified code to its commit. Eleven Node, 26 store and two CLI
process fixtures remain unexecuted. This qualifies the exercised debug source;
installed artifacts and the full M6 gates remain open.

Linux library `Node::open` now inspects the preserved catalog before creating
or changing the data directory or lock file. `open_locked` repeats admission
after acquiring the lock. Nine key/journal combinations verify unchanged
directory identity, mode and timestamps, original catalog/key/journal file sets
and bytes, and no new `.node.lock` file. Automatic daemon unlock reads and
verifies its configured seed before this preflight and lock/socket setup. A
real-process regression covers closed/WAL-only/live-WAL catalogs and wrong
identities, with no new lock or socket. Early Node admission qualification passes 38 unique cases (12 source-policy, 1
single-data-owner, 1 discovery-maintenance, 20 ordinary-process, plus four
provisioned native Git/backend/capture reopen cases). All four debug programs
build; format and strict locked workspace/all-targets Clippy pass. All 284
source files and six program/test-driver hashes remain unchanged, and native
mount/loop/image cleanup is verified. Evidence and the distinct passing-case
inventory are retained under `/tmp/mb-m6-early-admission-validation-u30_afvh`;
the post-commit audit binds the code to the commit. This is a focused
debug-source qualification; complete ordinary/native suites and installed
artifacts were not rerun.
Raw `lock_data_dir` and manual daemon lock/socket setup still precede
keyed admission; atomic writer/path/ownership handoff and rejection before every
filesystem mutation remain open.
The private WAL index uses memory proportional to its frame count; common R2/R3
metadata/resource budgets remain open.

Linux catalog export payload recovery and explicitly selected preserved parity
volumes now use reusable non-creating readers. Local signed-revision selection
runs in a short snapshot that ends before peer discovery. Export holds no
explicit transaction across the full recovery. Checkpoint/transcript scans now
fetch one owned bounded row per indexed key lookup, releasing the SQL cursor
before peer callbacks. Input guards run before each lookup and after callbacks,
rejecting changed inputs before another lookup or publication. A real SQLite
regression reproduces a busy WAL checkpoint with the previous streaming cursor;
the new callback permits checkpointing and then rejects the changed input.
Cursor qualification passes 63 unique cases (38 legacy-export, 1 large-
retained-graph, 2 legacy-discovery, 19 ordinary-process, 1 capture-withdrawal,
1 graph-intent-compatibility, and one provisioned Btrfs renamed-root case).
All four debug programs build; format and strict locked workspace/all-targets
Clippy pass. All 284 source files and six program/test-driver hashes remain
unchanged, and native mount/loop/image cleanup is verified. Evidence and the
distinct passing-case inventory are retained under `/tmp/mb-m6-recovery-
cursor-validation-h6i65pwl`; the post-commit audit binds the code to the
commit. This is a focused debug-source qualification; complete ordinary/native
suites and installed artifacts were not rerun.
Input guards require unchanged main/WAL versions and sidecar identity/absence
before staging and immediately before publication. Existing live SHM read marks
remain transient. Fixed and variable parity loads also check versions before and
after reading. A changed input rejects publication and removes owned staging
through the pinned output parent. No repair, schema migration or key publication
occurs. The export/parity reader increment was qualified on Linux on 2026-10-08 with
966 unique passing cases: 477 ordinary Node, 290 store, 102 Git and 19 CLI
process tests, all 64 provisioned Git cases, 11 native Node cases, extent
sharing/prune, stock-Git bridge and raw Unix CLI/daemon/Git paths. Closed, live
WAL/SHM and WAL-only control and parity fixtures preserve original bytes/file
sets across legacy/wrapped/interrupted-rekey keys. Missing, partial and corrupt
journals reject without repair. Input changes before staging or during
construction reject publication and remove owned staging. All four debug
programs build; formatting and strict locked workspace/all-targets Clippy pass.
All 284 source files and ten program/test drivers retain their hashes through
qualification, and native mount/loop/image cleanup is verified. Evidence and the
distinct passing-case inventory are retained under `/tmp/mb-m6-payload-validation-756jxsvu`;
the post-commit audit binds the code to the commit. Eleven Node, 26 store and two
CLI process fixtures and installed-artifact qualification remain open. Atomic writer/
path/ownership handoff, complete key-manifest and external-owner reconciliation,
other-platform reader qualification and common resource budgets remain open.

The report's `signed_format` describes the public revision format, not private
namespace format 6/7. `retained_history_complete` is false: available metadata
cannot prove that all peer history, external Git catalogs, refs, pins, worktrees,
pending intents and other anchor owners have been inventoried. Listing a revision
does not prove recoverable ciphertext or replacement protection. Preserve those
inputs and use its `revision_id` with `legacy-export` to verify an individual export.

Alternatively, select a revision from a preserved installation:

```sh
mutualbackup legacy-export \
  --data-dir /preserved/installation \
  --revision-id REVISION-UUID \
  --destination /exports/revision-001 \
  --seed-file /preserved/recovery.txt
```

This mode opens the control catalog read-only, using its existing wrapped key or
legacy seed-derived key. It searches saved revisions, recovery heads and certified
checkpoint history, then uses recovered Inline sources, verified cached recovery
shards or the certified local reconstruction described below. The destination's parent must be outside the installation. It performs no
key wrapping, schema migration, journal replay, source-hint update or cache
retirement. Without an explicit anchor area, it does not open anchor files.
Revisions requiring unavailable ciphertext or uncached packed reconstruction
still fail while preserving their original state. The command
exports the requested revision only; it does not inventory all retained history.
File inputs and catalog inputs are mutually exclusive.

When a requested sector is not directly available, catalog mode can reconstruct
it from preserved checkpoint data. The checkpoint must be canonical, carry the
exact owner/writer-signed revision and verify its quorum signatures under its
recorded hash. For historical fixed 3+2 groups, any three valid positions from
the recovery cache or explicitly selected preserved parity volumes
can recover the codeword; every reconstructed shard root and the coding relation
are checked. Zero-length filler positions are inferred only when their certified
full-sector root authenticates all-zero bytes. Cache rows from another checkpoint,
guild or group cannot serve as reconstruction inputs.

For packed checkpoints, cached `packed-sector` records supply one authenticated
payload at a time. Descriptor identity, guild, roots/commitments and source chunk
hashes are checked; chunks from multiple packed sectors join into the exact
64 KiB ciphertext referenced by the signed revision. Missing, oversized or corrupt
records require another authenticated input or fail without publishing an export.
The reader caches one certified
checkpoint and one decoded codeword, and reads one packed payload at a time, rather than an
installation-wide payload map. It can try another certified checkpoint containing
the exact same signed revision if the first cannot reconstruct a sector.
Preserved local parity volumes can also supply intact variable information
positions. If those are absent, canonical `coding-group-transcript` records
must replay as verified and describe the exact certified packed sector ID and
commitment. Recovery uses the recorded variable geometry and storage keys,
authenticates each READY input, infers only authenticated virtual zeros, checks
every reconstructed commitment and the complete coding relation, and then
checks the certified packed descriptor and owner-signed output sector. A damaged
cached packed copy can fall back to those volumes. No transcript activates a
group or authorizes retirement during export.

Repeat `--parity-volume` for distinct local volumes encrypted by this recovery
identity. Each existing database is inspected without schema migration, rekeying,
registry reconciliation, shard writes or retirement. The destination must be
outside every selected volume. For example:

```sh
mutualbackup legacy-export \
  --data-dir /preserved/installation \
  --revision-id REVISION-UUID \
  --parity-volume /preserved/parity-1 \
  --parity-volume /preserved/parity-2 \
  --destination /exports/revision-001 \
  --seed-file /preserved/recovery.txt
```

Catalog export destinations must also resolve outside every known local source,
Git repository, retained anchor area and absolute remembered area location.
The same streamed record validation and directory-identity checks used for peer
placement reject unsafe or malformed ownership before the export catalog reader
opens. File mode applies these placement checks to its explicitly supplied
revision/ciphertext input directories. Both modes pin the checked output parent
before recovery reads, then create, clean up and publish through that directory
capability. Replacing its path during recovery cannot redirect output to the
replacement. The requested parent identity is checked again before staging and
publication; a changed parent rejects the export, and cleanup uses the original
directory capability. Complete external-owner inventory, aliases through mounted
subdirectories and concurrent directory reparenting or ownership changes remain
R1 gaps.

Destination validation and parent pinning were qualified on Linux on 2026-10-08
with 61 unique passing cases: 37 inventory/export/peer cases, two discovery cases,
19 ordinary CLI process cases, two compatibility cases and one provisioned Btrfs
regression. Actual CLI destinations inside registered source/history directories
and symlink aliases reject with unchanged catalogs and source file sets. Wrapped
and legacy keys, old schemas, raw graph/anchor/cache owners, late malformed
records, placement beyond the report budget and renamed native roots are covered.
Parent replacement before staging and during construction rejects without
publication or writes to the replacement; cleanup removes the owned staging
through its original directory capability. All four debug programs build; format
and strict workspace/all-targets Clippy pass. Source and six program/test-driver
hashes remain unchanged through qualification, and mount/loop/image cleanup is
verified. Three CLI process fixtures remain ignored. Installed artifacts and
the full R1/M6 release gates remain open.

Unavailable inputs can also come from explicitly selected surviving peers.
Repeat `--peer NODE-ID=MULTIADDR` in catalog mode; the multiaddress must end in
the peer ID belonging to that node identity. For example, add
`--peer NODE-ID=/ip4/ADDRESS/udp/PORT/quic-v1/p2p/PEER-ID` to the command above.
The client uses a separate private temporary workspace and the recovered
identity's authenticated transport. It never starts the original installation,
publishes recovery state, repairs shards, enrolls a root or retires source data.
Original catalog, key and selected local volume state remain read-only.
`TMPDIR` must resolve outside the preserved installation, selected anchor/parity
areas, registered source roots, Git repository paths, typed guarded capture
anchor-area hints, pending capture source/area hints and recovery-replacement
source/area hints, pending Git blob source/area hints, retained anchors and
absolute remembered area locations. Peer mode uses inventory's non-creating snapshot reader and
shared canonical/shape validation, with a 32 MiB limit per local record. It streams
all relevant rows without building the inventory report or applying its aggregate
32 MiB report ceiling to placement checks. Placement state retains the temporary
parent's ancestry and one recent path hint; it does not grow with retained capture
count. Directory identities also reject aliases of existing inputs and renamed
roots identified by stable root/backend/stopped-capture and guarded plan records.
Ambiguous native plan identities conservatively exclude both current device/inode
and stable filesystem/inode matches; that exclusion does not certify which
historical meaning was used. Missing old paths remain compatible with recovery;
registration formats 1/2 are not interpreted as stable filesystem/inode IDs.
If an inode could match a preserved root and its stable filesystem identity
cannot be verified, select another `TMPDIR`; client creation is refused.
The parent's ancestor identities are checked again after the scan, so replacement
during inspection fails before client creation.
Volume-root hints are discovery locations, not ownership of the entire volume.
An old device-based plan with a missing hint cannot identify a relocated root
after its device number changes. These checks cover known local records. External
Git catalogs/worktrees and their other intents, recipe/pin/volume owners,
relocated anchor-area discovery and concurrent path replacement still
require the remaining R1 isolation qualification. Preserve those inputs too.

Local shards and authenticated zeros are considered first. If insufficient,
the client requests only the remaining positions needed for reconstruction,
preferring explicitly selected assigned holders before emergency copies.
Fixed reads check exact length/flat roots; variable reads check the transcript's
commitments. The full decoded codeword and final signed output checks still
apply. Direct information-sector copies also require their owner-signed root.
An unavailable unused peer does not postpone a locally or remotely available
quorum. Existing peer guild authorization remains enforced.

When the preserved checkpoint is missing, the client can fetch a selected
peer's announced checkpoint through bounded, hash-checked pages. The complete
certificate must verify and contain the exact owner-signed revision. If the
revision record is also missing, a preserved signed installed-guild certificate
provides the guild and genesis identity for searching those peer heads. A
conflicting genesis, generation or hash is rejected; a bad peer copy does not
prevent trying another selected peer. Downloaded records stay in memory and
are not installed in the original catalog.

If the revision or its placement is absent from those heads, the client follows
their certified parent hashes. Every parent must have the same guild/genesis
and be exactly one generation older. A missing or corrupt copy is retried on
other selected peers. The search streams one certificate at a time, keeping
only a cursor for each selected head; it installs no history or progress state
in the preserved catalog. It checks available heads before walking history.

If packed reconstruction needs a missing coding transcript, the preserved
signed guild genesis also anchors event-page replay from selected peers. Each
complete page must verify before its Add events are used. Event pages and
transcripts use the existing peer frame bounds; replayed state is capped at
32 MiB and the search at one million events. The client retains replay state
and one page rather than a complete event-history vector.

The transcript must verify, match the certified group and its attempt authority,
and cover the exact packed descriptor/commitment. A bound Add supplies its
canonical transcript hash. A legacy unbound Add requires an existing quorum
binding from the original signers; recovery never requests new attestations.
Missing or corrupt event/transcript copies are retried across selected peers.
Verified geometry drives variable-shard reads and complete-codeword checking.
These records remain in memory and do not enroll or restore live guild state.

This does not discover peers through the recovery directory, unlock other
identities' volume databases or inventory/convert all retained revisions.
Missing parent/event links and missing legacy quorum bindings cannot be
invented or skipped. Keep historical metadata and peer-held history for the
remaining recovery work.

If a signed sector is available only in preserved anchor files, supply its area
explicitly. Repeat `--anchor-area` for distinct areas:

```sh
mutualbackup legacy-export \
  --data-dir /preserved/installation \
  --revision-id REVISION-UUID \
  --anchor-area /preserved/anchor-area \
  --destination /exports/revision-001 \
  --seed-file /preserved/recovery.txt
```

The directory must carry the original `.mutualbackup-anchor-area-v1` marker.
The exporter pins that directory and uses the recorded area/anchor IDs and raw
relative paths. It ignores old path, volume and filesystem hints, allowing a
relocated preserved copy. Marker and regular-file reads preserve access times;
missing no-atime permission fails instead of changing them. Symlinks, special
files, FUSE areas and nested mount crossings are rejected. No mount search,
guarded view, manifest migration or source-location update is used. Selected
ranges must re-encrypt to the exact signed sector roots and commitments.
Corruption, unavailable ranges and offset overflow fail without publishing an
export. The destination parent must also be outside every supplied anchor area.
Preserve original guarded ownership markers and pending intents; this reader
needs no changes to them and does not authorize their cleanup.

The destination must not already exist. Recovery input may instead come from
`--seed-stdin` or the existing non-echo prompt. No daemon socket or mount is
required. The export package contains `namespace/`, preserving the raw paths,
file lengths/sparse gaps, hard links, ownership, modes and timestamps recorded
by private format 6. Format 7 also creates `history.git/`, a stock Git bare
repository containing every recorded ref, reachable object and selected HEAD.
`export.json` identifies the revision and counts; `signed-revision.postcard`
retains the signed provenance. Legacy ACLs/xattrs or other attributes absent
from the signed format cannot be reconstructed by this command.

All required sector roots and commitments are checked before output begins and
again when used. Missing metadata, unavailable sectors, mismatched signatures,
unsafe paths, ownership-setting failures or corrupt Git objects fail the export.
The package is built privately and published with a no-replace rename after
its files/directories are flushed. Failed construction never publishes the target.
A process crash can leave a private `.mutualbackup-legacy-export-*` staging
folder in the destination parent; preserve it for inspection rather than
changing the original installation to force a retry.

Export each retained signed revision separately. Independently compare exported
files and every Git ref/object against the preserved history, and run
`git --git-dir /exports/revision-001/history.git fsck --strict` where applicable.
Then enroll a separate qualified native source and verify durable replacement
protection. This command does not migrate original catalogs, enroll a root,
claim protection or authorize deletion of original history. If metadata or
sectors are unavailable, keep the original state and peer-held data for the
remaining recovery procedure; do not delete backend markers to bypass admission.

Prior catalog-export baseline (`a4c70d8`): six library fixtures and one actual
CLI fixture cover formats 6/7, raw paths, sparse files, hard links, recorded
ownership/modes/times, exact stock Git objects/refs/HEAD and strict Git fsck.
They reject missing/corrupt/changing inputs, unauthorized and oversized revisions,
input symlinks, wrong blob lengths/OIDs and nonempty destinations. The actual CLI
runs without a daemon and leaves signed revision, ciphertext and recovery-string
inputs unchanged. Catalog fixtures cover legacy/wrapped keys, both recovery-head
key layouts, certified checkpoint history, mixed Inline/cache sources, unchanged
database/key/journal state and preserved legacy schema. Two store fixtures check
bounded payload/key reads and damaged recovery-cache rows. All 104 core, 103
ordinary store, 87 ordinary Git, 370 ordinary
Node and 16 CLI-library tests pass, plus three CLI and seven mutualgit unit tests.
All eight provisioned snapshot regressions pass on disposable Btrfs with verified
mount/image/loop cleanup, along with formatting and strict workspace/all-targets
Clippy. Ordinary suites retain 18 store, 62 Git and 20 Node provisioned cases;
only the eight snapshot cases ran separately. The actual CLI also exercises
catalog extraction and rejects incomplete catalog flags. This is available-input export
qualification; it does not close remote extraction, complete
retained-history conversion or the full M6 upgrade/source-loss/platform gates.

The explicit-anchor increment is checked by the 105 ordinary store tests, eight
Node exporter/range fixtures, four CLI unit tests and the actual offline CLI
fixture. It covers relocated historical and raw-path locators, exact bytes and
unchanged marker/payload times, pinned-directory replacement, invalid markers,
symlinks, traversal, special files, unavailable/overflowing ranges and conflicting
CLI inputs. On disposable Btrfs, eight snapshot regressions and the new nested
mount rejection pass with verified mount/image/loop cleanup. Formatting and strict
workspace/all-targets Clippy pass. This increment does not rerun the complete
ordinary Node/Git suites or qualify all retained history, peer/packed reconstruction
or the full M6 upgrade/source-loss/platform requirements.

The certified-cache increment is checked by all 104 core and 105 ordinary store
cases, ten targeted Node exporter/range cases, four CLI unit tests and the real
CLI fixture. It covers all ten fixed three-of-five subsets, alternate certified
copies, foreign scopes, invalid quorum and corrupt shards; formats 6/7 exercise
split packed metadata/data and missing, oversized, corrupt or substituted records.
The real CLI recovers metadata and file data with the original information
positions absent and leaves the preserved database/key state unchanged. Eight
provisioned snapshot regressions pass with verified disposable Btrfs cleanup;
formatting and strict workspace/all-targets Clippy pass. This validation does not
include complete ordinary Node/Git suites, all other provisioned cases or the
full retained-history, peer/variable-volume and M6 platform/release requirements.

The library now provides a read-only preserved parity-volume reader for existing
seed-derived or wrapped SQLCipher keys, including an interrupted key-wrap
transition. It validates supported historical schemas without upgrading them,
requires an owner-signed volume manifest when present, and returns only READY
fixed/variable payloads matching the supplied guild and root/commitment. Reads
bound damaged database fields before allocation. `legacy-export --parity-volume`
now uses this reader for the recovery paths described above. Complete retained
history conversion and remote extraction remain open.

The parity-volume export increment passes 104 core and 108 ordinary store tests,
ten targeted exporter/range tests, two preserved-volume reader tests, four CLI
unit tests and the real offline CLI fixture (229 unique cases). Formats 6/7
exercise all six two-of-four subsets, intact information without a transcript,
authenticated zero positions, damaged-cache fallback, rejected insufficient,
STAGED, foreign, damaged or invalidly signed inputs, duplicate volume IDs and
destinations inside selected volumes. The real CLI combines a cached information
position with preserved fixed parity while both original information objects
are absent. Catalog and parity database bytes remain unchanged. Formatting and
strict workspace/all-targets Clippy pass. This increment does not rerun complete
ordinary Node/Git suites, provisioned cases or the full M6 release requirements.

The explicit-peer increment passes 104 core and 108 ordinary store tests,
twelve targeted exporter/recovery tests, two preserved-volume reader tests,
one wire frame-bound test, four CLI unit tests and the real CLI fixture
(232 unique cases). Real authenticated survivors recover formats 6/7 while
normal startup rejects the withdrawn owner catalog. Insufficient survivors,
a wrong recovery identity and valid stored peer bytes with a conflicting
certified root fail without publication. An unused unavailable peer does not
delay an available quorum. Original catalog bytes and absent key/parity files
are preserved, and temporary client directories are cleaned up. CLI peer mode
with cached inputs and confined `TMPDIR` rejection also pass. Formatting and
strict workspace/all-targets Clippy pass. Real variable/relay/Tor peer export,
complete ordinary Node/Git suites, provisioned cases and full M6 qualification
remain open.

The checkpoint-head metadata increment also passes three shared checkpoint-sync
regressions (235 unique cases with the suites above), formatting and strict
workspace/all-targets Clippy. The live format-6/7 fixture exports with a missing
checkpoint, then with both revision and checkpoint records missing. A corrupt
peer certificate falls back to another copy. Conflicting signed genesis, absent
guild certificate, unknown revision and a different valid signed revision with
the same ID fail without publication. Each attempt preserves the original
database bytes and leaves key/parity files absent. This does not qualify older
checkpoint traversal, event/transcript fetching or complete retained-history
conversion, and the full M6 release gates remain open.

The older-checkpoint increment passes thirteen exporter/recovery tests, the real
CLI fixture and the core/store/reader/frame/sync/CLI suites above (236 unique
cases). Real format-6/7 survivors recover a revision absent from their current
heads, including two parent links with a saved revision record and fallback to
the only valid parent copy. Missing links, generation skips and a foreign-genesis
parent fail without publication or original-catalog changes. The strengthened
two-link fixture was also rerun separately. Formatting and strict workspace/
all-targets Clippy pass. Event/transcript fetching, retained-history inventory/
conversion and full M6 platform/release qualification remain required.

The event/transcript increment passes fourteen exporter/recovery cases, the real
CLI fixture and 104 core, 108 ordinary store, two reader, one frame-bound, three
sync, eight wire and four CLI unit tests (245 unique cases), formatting and strict
workspace/all-targets Clippy. Real format-6/7 survivors serve 2+2 variable parity
at 64 KiB with both information positions absent and no local ciphertexts or
transcripts. Both bound and legacy unbound Add evidence work; corrupt event
sources fall back. Too few survivors, corrupt transcripts, invalid event
signatures and missing legacy bindings fail without publication. Missing original
checkpoint/revision records also recover. Original inputs and client cleanup are
checked. This exposed and fixes the version-one coding-plan CBOR tuple-length
bug; signed bytes and CBOR encoding are unchanged, with all three plan versions
and malformed tuples covered by the codec regression.

Peer-head lookup now supports an owner admitted after genesis using authenticated
membership-event replay. A historical prefix must match the checkpoint's active
roster, membership epoch and quorum and include the owner in its membership
history. Retained revisions can be exported after that owner is removed. Peers
allow historical members to read checkpoint heads/pages and event evidence;
mutation and live enrollment authorization are unchanged. Replay installs no
state in the original catalog. Original-genesis owners and available local
exports avoid the extra membership-history requests.

The later-member increment passes fifteen exporter/recovery, one durable
membership, eight wire, three checkpoint-sync, four CLI unit tests and the real
CLI fixture (32 targeted functions). The real new format-6/7 fixture has no local
checkpoint/revision records and exercises active and removed-member success,
invalid signed events/parents/admissions and an otherwise valid signed checkpoint
with an unsupported epoch. Output raw bytes and stock Git opening, unchanged
original catalog bytes, absent key/parity files and temporary client cleanup are
checked. Locked workspace/all-targets build, formatting and strict Clippy pass.
Complete core/store/ordinary Node/Git suites are not rerun for this increment.

Directory discovery, complete retained-history conversion, broader variable/
relay/Tor qualification and the full M6 release gates remain open.

The local inventory increment passes two inventory, five CLI unit tests and the
real offline CLI fixture (eight targeted functions), locked workspace/all-targets
build, formatting and strict Clippy. Format-6/7 metadata without ciphertext covers
wrapped/legacy database keys, distinct retained revisions, duplicate provenance,
foreign owners and summary-budget boundaries. Invalid scopes/IDs, owner/writer
signatures, checkpoint certificates/hashes and conflicting valid signed records
fail while preserving original inputs. The CLI lists revision IDs before export.
Complete ordinary Node/Git/core/store suites and full M6 gates were not rerun.

The selected-peer inventory increment passes seventeen exporter/inventory, one
membership, eight wire, three checkpoint-sync, five CLI unit tests and the real
CLI fixture (35 distinct functions), plus the final signed-history rerun,
formatting, locked workspace/all-targets build and strict Clippy. Real formats
6/7 cover peer-only revision metadata, current/older retained revisions, two
parent links, mixed provenance, corrupt-copy fallback and explicit gaps for
missing/skipped/foreign parents. Later and removed members require certified
replay; unsupported checkpoint epochs report unmatched owner authority. The CLI
rejects absent preserved genesis without partial JSON. Original catalogs and
absent key/parity files are preserved and temporary clients are cleaned up.
Complete ordinary core/store/Node/Git suites and full M6 gates remain open.

The Kademlia discovery increment passes two discovery, seventeen exporter/
inventory, one membership, eight wire, three checkpoint-sync, five CLI unit tests
and the real CLI fixture (37 distinct functions), plus the final discovery rerun,
locked workspace/all-targets build, formatting and strict Clippy. The real direct-
QUIC fixture gives the recovering client only a directory address; signed bundles
supply the survivor endpoint for inventory and export of formats 6/7, including
original and rotated-key locators. The directory contact is not selected as a
survivor. Cryptographic cases reject expired, wrong-context/identity, invalidly
signed, tampered and equivocal evidence and oversized records/query counts. CLI
parsing and absent-genesis rejection pass. Original catalog bytes, absent key/
parity files and temporary client cleanup are checked. Full ordinary/provisioned/
platform suites, relay/Tor discovery and all M6 release gates remain open.
