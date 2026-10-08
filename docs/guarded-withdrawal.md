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

Report format 2 includes preserved local protected-root registrations, backend
bindings, Git registrations and guarded stopped/revision-capture anchor ownership.
Raw Unix paths are reported as hex bytes. These records and the local signed
revisions come from one read-only SQLite snapshot, released before peer requests.
The complete canonical encoded report has a 32 MiB metadata limit; exceeding it fails the
inventory instead of returning a truncated success. Binding identity comparisons
are unknown for missing roots and older registration formats 1/2. Git registrations
can be history-only: `catalog_inventoried` remains false because the external Git
catalog is not opened. Unknown guarded/link-freeze records are listed with their
kind, ID, payload size and digest for preservation; they are not decoded ownership.
Source paths, mount paths and anchor payloads are not opened during inventory,
so `payloads_verified` remains false even when signed revision metadata is available.

Inventory opens forbid database/journal creation and deletion. A catalog with no
journal files uses an immutable read only while its file identity, size, mtime,
ctime and journal absence remain unchanged; a concurrent change fails the whole
inventory. Existing WAL/SHM pairs use SQLite read snapshots without checkpointing
the original database or WAL. Incomplete WAL/SHM pairs and rollback journals are
rejected before SQLite opens them. Preserve all files from that installation and
inspect a separate complete snapshot; never delete or checkpoint its original
journals to make an inventory succeed. These stricter opens currently apply to
`legacy-list`; the other legacy catalog readers still require separate no-creation
qualification under R1.

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

Unavailable inputs can also come from explicitly selected surviving peers.
Repeat `--peer NODE-ID=MULTIADDR` in catalog mode; the multiaddress must end in
the peer ID belonging to that node identity. For example, add
`--peer NODE-ID=/ip4/ADDRESS/udp/PORT/quic-v1/p2p/PEER-ID` to the command above.
The client uses a separate private temporary workspace and the recovered
identity's authenticated transport. It never starts the original installation,
publishes recovery state, repairs shards, enrolls a root or retires source data.
Original catalog, key and selected local volume state remain read-only.
`TMPDIR` must resolve outside the preserved installation, selected anchor/parity
areas, registered source roots, Git repository paths and typed guarded capture
anchor-area hints. Peer mode reads these exclusions with the same bounded,
non-creating snapshot reader used by inventory, including its 32 MiB local-state
budget. Directory identities also reject
aliases of existing inputs and renamed roots identified by stable root/backend/
stopped-capture records. Missing old paths remain compatible with recovery;
registration formats 1/2 are not interpreted as stable filesystem/inode IDs.
If an inode could match a preserved root and its stable filesystem identity
cannot be verified, select another `TMPDIR`; client creation is refused.
Volume-root hints are discovery locations, not ownership of the entire volume.
These checks cover known local records. External Git worktrees, other pending
owners, relocated anchor-area discovery and concurrent path replacement still
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
