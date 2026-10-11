# Bounded authenticated catalogs for the 1 TiB release target

Status: page/record framing, typed source records, paged Git container and legacy adapter, local ownership, address/encryption primitives and a bounded signed paged revision codec implemented; production admission
remains disabled until the complete R2/R3 acceptance gates pass. Existing revision/checkpoint formats
and their limits continue to apply.

## Problem and required capacity

The user selected 1 TiB per protected dataset, including retained history, on
2026-10-06. The current revision contains flat sector-reference and commitment
vectors. Private file metadata, the Git graph, packing maps, coding groups and
checkpoint revisions also contain flat collections. The existing transport
pages split one bounded serialized object and then reassemble it in memory;
they do not provide a scalable catalog.

A larger constant would allow one writer to publish state that another reader,
signer, checkpoint, packing or recovery path cannot process. Git already has
that historical problem: older local graphs can exceed the backup descriptor
bound. Current mutation checks cover the complete Git descriptor, but the full
enclosing native/private and signed revision contract remains open.

## Direction

Use immutable, content-addressed trees of bounded catalog pages. A small root
authenticates each page's bytes, order, subtree length and page count. Hashes
bind a format version, catalog scope and section. Dataset sections bind the
guild, owner and protected root; shared packing/coding sections bind the guild
without inventing a dataset owner. Children strictly
decrease in height, so traversal cannot follow a cycle or exceed a fixed depth.
The page decoder checks encoded length and the expected reference before
interpreting the page. A consumer verifies every page it uses against its
authenticated parent, rather than trusting a peer's self-reported page hash.

The page primitive bounds encoded pages to 64 KiB, leaf payloads to
60 KiB, index fanout to 128, height to three index levels, and a section's
represented metadata to 16 GiB. These are metadata bounds, separate from the
1 TiB protected-data target. A streaming builder retains one partial leaf and
at most one index per level. Its storage callback must persist pages before
the caller publishes the root. Streaming traversal retains the bounded path
and processes leaf records incrementally. Neither path assembles a catalog
into a single vector.

The initial byte-stream builder covers full capture and format migration.
Incremental record updates still need authenticated seek/edit operations and
stable record boundaries so a changed file rewrites its pages and index path
instead of regenerating an entire section. Qualification must measure both
buffered memory and work performed for small changes to a large retained
catalog; deduplicated storage alone does not demonstrate bounded update work.

Separate sections cover file entries and extent recipes, Git refs and object
fragments, sector references and source commitments, packing/source proofs,
and coding/retirement descriptors. Large individual Git trees and file extent
lists require bounded record fragments too; opaque byte pages alone do not
fix those allocations. Private sections remain owner-encrypted. Public
packing/coding sections retain their existing authenticated authority. Page
addressing, encryption and source-sector regeneration must bind the same
scope and section as page hashing.

New signed revision and checkpoint formats carry section roots and bounded
summary counts rather than the corresponding flat collections. The paged
revision/private migration codec reserves format 8; a new checkpoint version
will be assigned as its consumers migrate. Withdrawn
guarded private metadata formats 6/7 must never be reinterpreted as native
paged catalogs. Existing decoders and signed bytes remain unchanged.

## Admission, publication and retirement

One versioned capacity policy must be used by Git mutation preflight, native
capture, descriptor generation and recovery. In addition to the 1 TiB target,
it must specify file/namespace, extent, Git object/ref and retained-revision
limits, and how sparse logical lengths, shared inodes and unchanged historical
objects are counted. Those policy limits must be exercised before production
admission is enabled; the page primitive does not establish them.

Mutation preflight uses a prospective graph and capture manifest, counting the
actual record/page encoding and enclosing signed roots. It must finish before
visible refs, index state or protection claims are published. Oversized
existing history remains readable and exportable. Status identifies the failed
limit and the supported migration/export remedy without trimming history.

Pages belong to a durable capture/import intent until its root is committed.
Interrupted writes leave resumable ownership, not a published partial tree.
Replay validates the signed root and all required page paths before activation.
Pruning marks retained roots and streams their references using bounded local
database work; it must preserve shared pages and pending intents. Seed-only
recovery obtains authenticated roots first, then fetches and verifies pages
incrementally. Missing or corrupt pages block the affected operation.

## Implementation and qualification order

1. Add the bounded tree codec, streaming builder and authenticated traversal.
   Test order/substitution, corruption, malformed counts/heights, encoding
   boundaries and storage failure without an emitted root.
2. Add durable page ownership and public/private addressing, then bounded
   record codecs and iterators. Qualify reopen and cancellation at each write
   and publication boundary.
3. Introduce revision/Git roots and shared capacity preflight. Preserve legacy
   decoding and qualify atomic rejected commit/ref/merge/import mutations.
4. Migrate packing, coding/checkpoint replay and retention together. Preserve
   exact existing proofs, signer authority and physical cleanup semantics.
5. Qualify dense/sparse files, hard links, many small files, retained Git
   history, above-old-limit datasets, the 1 TiB boundary, interrupted backup,
   prune and seed-only recovery with measured memory/work bounds. Structural
   or synthetic scale tests supplement actual data tests; they do not count
   as a successful 1 TiB backup/recovery run.

The first increment is implemented in `crates/mb-core/src/catalog.rs`: bounded
encoding/decoding, streaming construction and ordered authenticated traversal.
Eight targeted tests and all 58 core tests pass, including legacy format
fixtures; formatting and strict workspace/all-targets Clippy pass. Exact-limit
metadata trees use repeated subtrees to exercise structural counts with bounded
construction. They do not establish real data capacity, durable page ownership,
incremental update work or end-to-end production support. Steps 2–5 remain open.

Local ownership is now implemented separately in
`crates/mb-store/src/database/catalog.rs`, using versioned protocol records in
the existing SQLCipher schema. Immutable page payloads and metadata are stored
with intent pins and parent links in one transaction. Each index is accepted
only after its immediate children are durable and verified; their existing
parent links retain the rest of the closure. Publishing a local root changes
the intent state atomically and retains its root pin. Surplus construction pins
can then be released one per transaction. Cancellation fences further writes
and publication before releasing any pin. A durable candidate queue collects
one unreferenced page and its bounded outgoing links per transaction, without
rescanning an entire catalog for every deletion. Pending and published shared
roots preserve the same immutable descendants through cancellation and reopen.

Each intent bounds its owned page count and records encoded-byte accounting.
Payloads and keys are bounded by SQL before allocation, then validated against
their expected metadata and page hashes. Four targeted ownership fixtures pass
at each page-write, publication, pin-release and page-collection reopen boundary,
including corruption and injected SQL failures. All 58 core and 79 ordinary
store tests pass; 18 provisioned store tests remain ignored. Formatting and
strict workspace/all-targets Clippy pass.

This local root is not a signed revision or a protection claim. At-rest storage
uses SQLCipher. Address/encryption primitives are implemented below; daemon
protocol integration and public authority checks remain open. Cancelled intent records remain as small fencing
tombstones until an authenticated generation-floor mechanism can retire them.
Quota/headroom reservation, record codecs, incremental updates and integration
with capture, packing, checkpoint replay, retention and seed-only recovery
remain open. Local ownership alone does not enable the 1 TiB target.

Page address/encryption primitives are implemented in
`crates/mb-core/src/catalog/privacy.rs`. File metadata and Git graph sections
are private; source references, packing and coding sections are public to their
authorized peers. A private page's storage ID is a keyed, versioned hash of the
scope, section and complete authenticated page reference. It can be derived
from a parent reference and seed-derived identity key before obtaining the
child's plaintext. Public addresses use a distinct unkeyed domain and private
sections cannot use that path. Fixed address vectors preserve the version-one
encoding and domains.

Private sealing first validates the encoded page, then uses the existing
64 KiB encrypted-sector representation. Opening checks the derived storage ID,
logical/physical lengths, ciphertext root, canonical zero padding and exact
authenticated plaintext page. Regeneration preserves ciphertext, flat roots
and Merkle commitments; missing information pages reconstruct byte-for-byte
through the existing coding path. Private plaintext page hashes/references must
stay inside authenticated owner-encrypted metadata; only keyed IDs and signed
ciphertext/source commitments belong in peer-visible catalogs. Public lookup
addresses do not supply signature or membership authority by themselves.

Seven new crypto fixtures and all 19 catalog tests pass, including fixed
vectors, corruption/rehashed corruption, key/scope/section mismatches, sector
geometry and padding, seed-derived encrypted tree traversal, and missing-page
reconstruction. All 65 core tests, formatting and strict workspace/all-targets
Clippy pass. The seed fixture proves cryptographic lookup/traversal, not an
end-to-end daemon or 1 TiB restore. Signed revision/checkpoint binding, peer
authorization, page transport, source recipes and runtime consumer migration
remain open.

Bounded record framing is implemented in
`crates/mb-core/src/catalog/records.rs`. A versioned stream header precedes
length-prefixed records of at most 48 KiB. The root binds the declared record
count and authenticated page reference; an enclosing signed or owner-encrypted
root must authenticate both together. The builder serializes into a fixed
buffer and rejects oversized values before publication. The reader handles
headers and payloads crossing leaf boundaries, bounds each allocation, and
checks final EOF before returning the final declared record. Any storage,
fetch or framing failure fences continued use.

Five new fixtures cover encoded size boundaries, cross-page framing, empty
streams, malformed/truncated/oversized/trailing frames and failure fencing.
All 24 catalog tests and all 70 core tests pass, along with formatting and
strict workspace/all-targets Clippy. Records returned by this reader are raw
bounded bytes: schema-specific decoders must still bound nested collections
and validate canonical encoding and semantics. Typed record fragments,
incremental seek/edit, quota reservation and runtime integration remain open.

Typed source records are implemented in
`crates/mb-core/src/catalog/sectors.rs`. Each version-one fixed-size record
pairs a `SectorRef` with the existing `MerkleCommitment`. The decoder bounds
encoded bytes, uses only fixed-size fields, checks canonical encoding and
validates logical length and full encrypted-sector commitment geometry.
Ciphertext flat roots and Merkle roots remain distinct authenticated values.
Builders and readers enforce strictly increasing sector IDs, rejecting
duplicate or conflicting sources without allocating a catalog-sized map.

The source root binds the record root and total logical source bytes; consumers
must authenticate both in the enclosing revision. The reader checks this
summary before yielding the final source. Unique-source logical bytes are
accounting evidence, not a retained-dataset capacity or physical quota measure.
Five fixtures cover multi-page streaming, malformed schema/encoding/geometry,
ordering and duplicates, summary substitution, and terminal storage/fetch
failure. All 29 catalog tests and all 75 core tests pass, along with formatting
and strict workspace/all-targets Clippy. Signed revision integration, shared
admission policy and file/Git/packing/coding record fragments remain open.

Git metadata-object fragmentation is implemented in
`crates/mb-git/src/object_catalog.rs`. Each commit/tree/tag has a bounded header
followed by canonical 32 KiB fragments (the final fragment may be shorter).
The builder reads an isolated object's input incrementally and requires its
exact declared length. The reader enforces increasing OIDs, contiguous offsets,
fragment geometry and complete objects. Both verify Git's type/length-prefixed
SHA-1 OID incrementally; the final fragment is withheld if the object hash or
authenticated count/byte summary fails. Blob payloads stay in source anchors.
Oversized nested fragment declarations reject before allocating their contents.

Six fixtures cover object kinds, empty trees, cross-page fragments, malformed
declarations/encoding, ordering, hash/geometry/summary corruption, truncation,
extra input and terminal input/storage/fetch failures. A generated tag larger
than the old 32 MiB descriptor bound streams through the codec and regenerates
its exact OID using independent libgit2 write streams. All 55 ordinary Git tests
pass (62 provisioned tests remain ignored), with formatting and strict
workspace/all-targets Clippy.

This object stream is not a complete Git descriptor or a protection claim.
Its root and summary require authentication inside the owner-encrypted Git
container. Consumers must reach verified EOF before activating staged objects,
retain libgit2's parsing/collision checks and validate the full graph's refs,
blob availability and reachability. Git ref/blob fragments, the shared admission
policy, bounded DAG validation, legacy migration and daemon integration remain
open; existing graph and descriptor limits are still enforced.

Sparse Git blob recipe records are implemented in
`crates/mb-git/src/blob_catalog.rs`. Blob headers bind OID, logical length and
extent/sector occurrence counts. Extent headers bind offset, byte coverage and
sector count; following canonical fragments contain up to 128 sector references.
Repeated references retain their exact order. Construction and traversal retain
only the current blob/extent counters and a bounded fragment. The legacy adapter
iterates an existing `GitBackupBlob` without copying its full extent/sector list.
It does not change existing signed descriptor bytes or runtime admission.

Readers check increasing blob OIDs, nonoverlapping in-bounds extents, arithmetic,
fragment indices and counts, source-sector geometry and exact extent coverage.
The authenticated root summarizes blob/extent/sector counts, logical bytes
including holes, and data bytes. Totals are checked before the final record is
returned. Source occurrences count repeatedly; these totals are not physical
quota or the retained-dataset admission policy. Nested sector declarations are
bounded before allocation. Incomplete recipes and failures cannot publish a root.

Six fixtures cover legacy sparse conversion across pages, repeated references,
empty/all-hole blobs, overlap/overflow/truncation/count/order corruption,
canonical encoding, summary substitution and terminal storage/fetch failures.
All 61 ordinary Git tests pass (62 provisioned tests remain ignored), along
with formatting and strict workspace/all-targets Clippy. The synthetic 1 TiB
logical sparse blob preserves exact recipe layout but does not demonstrate a
real 1 TiB backup or restore. The enclosing Git container must authenticate this
root and join recipes against signed source references; recovery must hash the
regenerated plaintext blob. Those consumers, ref records, full DAG validation,
legacy migration and the shared capacity policy remain open.

Git refs and a complete paged Git container are implemented in
`crates/mb-git/src/ref_catalog.rs` and `crates/mb-git/src/paged_catalog.rs`.
Version-one ref names are bounded to 8 KiB and selected branch names to 1 KiB,
with declarations checked before allocation. Component ordering, rather than
ordinary byte ordering, makes a parent ref immediately precede its descendants.
Thus one previous name suffices to reject namespace conflicts, duplicates and
reordering, including `foo`, `foo-bar`, `foo/x`. The root authenticates the
selected branch and its exact OID, or an explicit unborn selection; traversal
checks this before yielding the final ref.

The enclosing container binds repository identity and the three typed roots in
at most 4 KiB. Their represented metadata bytes and page occurrences share the
existing 16 GiB / one-million-occurrence bounds, rather than each section
independently admitting the whole budget. This is a structural metadata bound,
not physical quota or the complete retained-dataset policy.

`GitBackupDescriptor::write_paged_catalog` first validates a supported legacy
descriptor and checks the new name bounds before emitting any pages. It sorts
borrowed indices into the already bounded legacy value and streams exact refs,
object bytes and blob recipes without rewriting the original signed bytes.
Oversized/unsupported existing history remains on its original path; this
adapter does not enable new runtime admission. New capture/recovery paths must
provide ordered streams directly, rather than assemble a larger legacy value.

Five ref fixtures and four combined-container fixtures pass, covering name
boundaries, namespace conflicts, selected/unborn branches, encoding, failures,
aggregate geometry, legacy round trips and control-store reopen. All 50 catalog
tests and 70 ordinary Git tests pass (62 provisioned Git tests remain ignored),
with formatting and strict workspace/all-targets Clippy. The reopen fixture
retains a building intent and verifies staged pages and a locally stored root;
it does not publish a signed revision or prove remote/seed-only recovery.

Each stream still needs durable ownership. An opaque container leaf does not
create the page store's authenticated index-child edges to its three streams;
atomic root-set publication and retention must explicitly retain them together.
Owner-encrypted root binding, source-authority joins, plaintext blob hashing,
bounded DAG validation, shared mutation preflight, daemon capture/recovery and
legacy migration integration remain open.

Atomic local multi-root ownership is implemented in
`crates/mb-store/src/database/catalog/bundle.rs`. A version-one bundle binds one
scope, an immutable descriptor of at most 4 KiB, and up to 16 existing intent/root
pairs. One writer transaction verifies and publishes all roots, their retained
pins, intent-to-bundle links and descriptor bytes together. Existing page/intent
formats and the control schema remain unchanged. Retries must match the complete
bundle; cancelled bundle IDs never resume. Links reject independent cancellation
of a published member. Bundle cancellation marks all members cancelled and
removes their links atomically before existing bounded cleanup can begin.

Shared and pending successor roots keep their own pins and immutable parent
closures. Publication/cancellation rollback covers every member and link even
when SQL aborts or silently ignores an update/delete. Intent writes now check
affected-row counts, fixing the prior unchecked-update path. Reads bound bundle
payloads to 8 KiB in SQL before allocation and bound nested root/descriptor
collections during decoding. A read transaction returns a consistent local
descriptor/member-state snapshot; traversal still verifies actual page bytes.

Four new fixtures cover publication/reopen, each pin-release/cancellation/GC
boundary, pending/published sharing, immutable retries, missing roots, scope,
collection/journal bounds, corruption and injected SQL abort/ignore failures.
All 54 catalog tests and 83 ordinary store tests pass (18 provisioned store
tests remain ignored), with formatting and strict workspace/all-targets Clippy.
This is local durable publication, not a signed revision or remote protection.
The caller must validate its typed descriptor against the manifest of retained
roots. Typed Git wiring, signed activation, quota reservation, retention policy
and generation-floor retirement of fencing journals remain open.

Typed Git bundle publication is now wired through `GitCatalogRoot` in
`crates/mb-git/src/paged_catalog.rs`. `write_paged_catalog_streams` supplies
explicit ref/object/blob roles so callers stage each stream under its own
intent. The original single-sink adapter remains compatible. Typed publication
constructs an exact three-root manifest and canonical descriptor before calling
the atomic bundle API. Typed reopen checks expected dataset scope and repository
identity, decodes the bounded descriptor, and compares every ordered role/root
against the bundle. A valid opaque store bundle with a substituted manifest is
rejected by the typed loader.

The earlier staging-only reopen fixture now publishes and reopens the complete
typed bundle, verifies all stream pins, releases surplus pins, restores exact
metadata/recipes, and cancels/collects it. Two additional fixtures cover ownership
substitution and an interrupted object stream with no published descriptor,
followed by cancellation, rejected stale retry and cleanup. All 56 catalog tests
and 72 ordinary Git tests pass (62 provisioned Git tests remain ignored), with
formatting and strict workspace/all-targets Clippy. These are local publication
and compatibility checks; they do not prove daemon capture, signed activation,
remote protection or seed-only recovery. Those consumers, source-authority joins,
plaintext blob hashing, shared admission and the 1 TiB qualification remain open.

The native file namespace codec is implemented in
`crates/mb-core/src/catalog/files.rs`. Version-one records bound raw relative
path bytes to 8 KiB and preserve the current mode and signed seconds/nanoseconds
fields. Slash-delimited components reject empty, absolute, dot, parent and NUL
names. The codec preserves non-UTF-8 bytes; runtime capture still needs its own
platform representability checks and migration. This does not define complete
ACL/xattr/Windows stream metadata support.

Component ordering keeps a directory subtree contiguous. Validation retains
only the previous path and active directory path: declared ancestors are prefixes
of that directory. Missing parents, children of files/aliases, duplicate paths
and reordering fail without a full namespace map. File keys equal their record
ordinal, including directories and aliases, and therefore cannot be substituted
or duplicated within a validated stream. Root attributes, entry-kind counts and
checked file/alias byte totals are authenticated together; traversal checks the
summary before yielding the final record and fences errors.

File records deliberately separate namespace/attributes from payload recipes.
They preserve hard-link group IDs but do not establish group consistency or
alias ownership. Separate bounded sparse extent/sector records must join against
these file keys and authenticated source references. Legacy conversion, joined
validation, durable file-root publication, native capture/restore migration and
capacity qualification remain required before this format is activated. Byte
totals count path occurrences, not physical quota or retained dataset usage.

Six fixtures cover multi-page raw-path/attribute/link-identity round trips,
namespace/schema/encoding/count bounds, overflow and terminal storage/fetch
failure. An independent directory-set check covers all 19,683 assignments of
absent/directory/file to a nested namespace. All 81 core tests and the workspace
catalog-filtered suite pass, with formatting and strict workspace/all-targets
Clippy. The 1 TiB logical length in a header is a structural fixture, not payload
capture, retained-history accounting or capacity qualification.

Native sparse payload recipes are implemented in
`crates/mb-core/src/catalog/file_recipes.rs`. File headers bind namespace record
ordinals to logical length and exact extent/sector occurrence counts. Extent
headers carry offsets and coverage; sector fragments contain at most 128
references. File keys are strictly increasing and bounded by the namespace
record geometry. Readers validate canonical schemas, fragment declarations
before collection allocation, overlap/overflow, fragment ordinals and exact
extent coverage with only the current file/extent counters. Repeated source
references preserve their occurrence order. Root totals are checked before
yielding the final record, and incomplete input or storage/fetch errors prevent
publication or continuation.

`push_file` bridges borrowed legacy extents in two passes to declare counts and
emit fragments; it never clones the complete extent or sector list. New capture
must provide bounded records directly. Logical bytes include sparse gaps and
data bytes count every extent occurrence. These totals do not establish source
authority, deduplicated physical usage or retained-history capacity. The file
namespace and recipe roots still require exact key/length, hard-link and signed
source joins, atomic typed publication and native runtime/legacy integration
before activation.

Five recipe fixtures cover borrowed multi-page conversion preserving exact
gaps/offsets/repeated references, empty/all-hole files, key/geometry/count/order
errors, malformed schema/encoding/declarations, final summaries and terminal
overflow/storage/fetch failures. All 86 core tests and 84 catalog-filtered
workspace tests pass (two provisioned tests remain ignored), with formatting and
strict workspace/all-targets Clippy. A synthetic 1 TiB sparse length exercises
recipe geometry; it does not qualify payload backup, restore or retained usage.

`crates/mb-core/src/catalog/native_files.rs` binds the namespace and recipe roots
in a fixed-field, canonical container of at most 1 KiB. Both streams share the
existing aggregate metadata/page-occurrence bounds and must agree on file count
and logical file bytes. Local publication must retain the two trees together;
an opaque container leaf alone does not create page-store child ownership.

The joined reader interleaves namespace entries with the corresponding recipe
header and bounded extent/sector fragments. Each file's exact namespace ordinal
and length must match its recipe before the file entry is returned. Directory
and hard-link alias entries have no independent recipe. Only the pending recipe
header and existing bounded reader buffers are retained. Missing, extra,
incomplete or substituted recipes fail, including substitutions which preserve
both streams' total counts and bytes. Both authenticated EOFs are checked before
yielding the final combined event, including catalogs ending in a directory,
alias, empty file or all-hole file. All failures fence continuation.

This establishes the namespace/recipe key and length join. Hard-link group
consistency, signed source-reference authority, typed durable publication,
legacy private metadata conversion and native capture/restore migration remain
activation requirements. The container does not claim physical quota, protection
or production capacity.

Seven fixtures cover interleaving across both trees' page boundaries, every
entry/recipe ending, exact key/length substitution despite matching summaries,
missing/extra/incomplete streams, page corruption, terminal fetch failure,
canonical encoding and aggregate metadata/page-occurrence boundaries. All 93
core tests and 91 catalog-filtered workspace tests pass (two provisioned tests
remain ignored), with formatting and strict workspace/all-targets Clippy.
These are structural join checks, not payload/retained-history
capacity qualification or signed activation evidence.

Native hard-link/source joins are implemented in
`crates/mb-store/src/database/catalog/native_validation.rs`. A validation manifest
binds dataset scope, the native file container and the public source root, with
one aggregate metadata/page-occurrence bound across all three streams. Callers
must authenticate those descriptors before validation; this API derives local
evidence and does not establish signed authority itself.

Validation first traverses the complete source catalog and writes fixed-size
rows indexed by sector ID. The joined native reader then checks each recipe's
exact sector ID, ciphertext root and logical length against that index. Only
bounded readers, one SQL row, a current file/hash and a bounded fragment are
held in application memory. Source records not referenced by native file
payloads remain legitimate: the revision may also own private metadata/Git
sectors. Ciphertext bytes and range proofs are checked by recovery/protection
consumers, not by this metadata join.

Hard-link groups are indexed by group ID. Mode, signed seconds/nanoseconds and
logical length must agree for every primary and alias. A domain-separated
incremental recipe hash includes sparse offsets, extent boundaries and exact
sector occurrence order, excluding the namespace file ordinal. Thus historical
duplicate primaries are accepted only for identical recipes; forward aliases
resolve to the first primary key encountered in namespace order. Any group
without a primary rejects at EOF.

One SQLCipher writer transaction commits lookup rows and the immutable completion
manifest only after all source/native EOFs and joins pass. Errors roll back the
entire derivation. This currently performs a full validation scan in one writer
transaction; incremental validation/update scheduling remains part of runtime
migration. Successful immutable retries use the derived completion record, not
a new ciphertext or bitrot certification. Lookup reads validate bounded canonical
rows in a consistent read transaction. Cancellation fences lookups and retries
before cleanup removes one index row per transaction; fencing journals remain
until generation-floor retirement is defined. Validation never publishes or
cancels the page roots or signed revision, and those pages need their own durable
ownership. Typed publication, legacy conversion and native consumer activation
remain open.

Five native validation fixtures cover forward aliases, duplicate primaries,
conflicting attributes/recipe identities, exact source substitutions, incorrect
source summaries, bounded cached-row reads, reopen and each cleanup boundary,
and SQL abort/ignore rollback at source/group/completion/cancellation/cleanup
writes. A multi-page fixture derives 3,200 source and group rows and reopens
indexed lookups, preserving repeated sector occurrences. The catalog-filtered
workspace suite passes 96 tests (two provisioned tests remain ignored). All 88
ordinary store tests pass (18 provisioned store tests remain ignored), with
formatting and strict workspace/all-targets Clippy. These fixtures establish
local metadata joins; no real payload or 1 TiB qualification is claimed.

Typed native publication now binds a completed validation manifest to its exact
namespace, recipe and source roots in `native_validation.rs`. The validation ID
is also the bundle ID. Construction checks the expected dataset scope, role
sections and unique intent ownership; publication checks the immutable completed
manifest inside the same writer transaction that publishes all retained root
pins and the native bundle link. Reopen validates canonical descriptor bytes,
every ordered role/root, bundle member state, validation state and native link in
one read transaction. A generic opaque bundle with substituted role order does
not become a valid typed native publication.

Published native bundles reject independent cancellation of their validation
index, generic bundle or member intents. Typed cancellation fences the index and
all three roots and removes their links atomically before bounded index/pin/page
cleanup. A retry must observe a consistent cancelled snapshot; the cancelled
bundle and validation IDs remain fenced after page reclamation. Existing generic
bundle logic is factored into transaction-local helpers so these related changes
share the transaction. Serialized bundle/validation/page formats and the control
schema remain unchanged. This is local publication; protocol signing, ciphertext
protection, legacy private metadata conversion and runtime migration remain open.

Three new publication fixtures cover exact typed reopen, independent-cancellation
fences, stale retries, each index/pin/page cleanup boundary, wrong scope/role/
ownership, generic descriptor/manifest substitution and injected SQL abort/ignore
rollback during joint publication and cancellation. All 91 ordinary store tests
and 72 ordinary Git tests pass (18 store and 62 Git provisioned tests remain
ignored), with formatting and strict workspace/all-targets Clippy. These checks
qualify local ownership/validation consistency rather than signed activation or
real 1 TiB payload/retained-history capacity.

`crates/mb-node/src/native_catalog.rs` adds borrowed conversion of the native
portion of decoded legacy private metadata. Formats 1–5 retain root/entry
attributes, dense and sparse recipes, repeated sector occurrences and hard-link
identities. Original-order primary/alias checks run before namespace sorting;
the durable group join can then resolve aliases that sort ahead of their primary.
Conversion counts the existing canonical encoding with a 32 MiB bounded serializer
and performs a dry bounded page pass before any external writes. It sorts borrowed
entry references and copies only bounded paths and recipe fragments. It does not
rewrite the original metadata or increase legacy admission limits.

The sink identifies namespace and recipe roles explicitly. The returned file
root still requires sources from the authenticated enclosing revision and the
native validator before typed publication. Formats 4/5 supply only their decoded
native portion to this adapter; their Git descriptor must also be retained and
converted separately. Unsupported versions and namespace shapes, including
missing explicit directory parents, stay on their existing legacy recovery path.
Withdrawn formats 6/7 remain rejected. This library adapter does not enable a new
capture, signed revision, restore or migration format.

Six adapter tests and 26 ordinary snapshot regressions pass (eight provisioned
snapshot tests remain ignored), with formatting and strict workspace/all-targets
Clippy. Coverage includes dense/sparse/empty files, forward sorted aliases,
repeated references across pages, bounded rejection before writes, sink failure,
local source validation/publication/reopen, both immutable version-2 wire
fixtures and decoded Git-bearing version-4/5 envelopes. Historical originals and
Git descriptors remain unchanged. These are metadata conversion checks; complete
historical migration, consumer activation and real 1 TiB qualification remain open.

Existing runtime encoding now uses `canonical_size_bounded` and
`canonical_bytes_bounded` from `crates/mb-core/src/canonical.rs`. Counting uses the
same Postcard serializer, includes all nested lengths and field overhead, stops
at an inclusive byte bound and allocates no complete encoding. Bounded encoding
then allocates the counted size and writes into that fixed buffer; even a
serializer whose output changes between passes cannot grow it. Ordinary encoding
errors remain distinct from a size-limit error. Deterministic values retain their
original wire bytes.

Git descriptor validation applies the existing 32 MiB bound before constructing
its temporary DAG repository. Native capture checks its anchor manifest without
encoding it, bounds the complete private metadata (including its Git descriptor)
before allocating the output, and counts the complete revision envelope with both
64-byte signatures before signing. The legacy native adapter shares the same
counter. These changes preserve current wire versions and inclusive limits.
They prevent allocating an oversized encoding merely to reject it; they do not
bound the already assembled model or resolve R2's 64 MiB local graph admission
mismatch. Commit/ref/merge/import preflights and a complete shared admission
contract remain required.

Six new fixtures cover exact canonical boundaries, early termination without
visiting the entire input, arithmetic overflow, serializer errors and changing
output, a valid Git graph just below/at/above the 32 MiB descriptor limit,
native/Git envelope overhead and both revision signatures. Native Git
capture/restore and rejected-capture repair pass on disposable Btrfs, with
verified mount/image/loop cleanup. These checks preserve legacy backup behavior;
they do not establish production capacity or end-to-end mutation admission.
All 96 core and 73 ordinary Git tests, 28 ordinary snapshot regressions and six
legacy adapter tests pass, with formatting and strict workspace/all-targets
Clippy. The ordinary suites retain 62 ignored Git and eight ignored snapshot
provisioned cases; the two named capture cases were run separately on Btrfs.

Local commit, branch, pin and tag publication now preflights the proposed full
reachable descriptor while holding the SQLite writer through publication.
`ControlStore::put_records_and_delete_checked` starts an immediate transaction,
runs a read-only caller check, checks affected write/deletion counts and commits
the batch only after success. A competing writer cannot add a ref between the
check and publication; SQL rejection or ignored writes roll back the batch.
Annotated tags publish their metadata object and ref together. Commits also
reject a changed selected branch or previous HEAD inside that transaction.

`history.rs` shares reachable graph traversal between export and proposed-record
preflight. Proposed metadata is hash-checked and overlaid in a temporary metadata
repository; refs include existing branches, remote refs, tags and pins. Export
retains its existing native anchor verification. Admission reads cached, mutually
consistent blob lengths from the already verified local mappings; it does not
read retained blob payloads. This geometry check is not a new payload certificate.

`backup_size.rs` uses a borrowed descriptor and virtual dense blob/extent/sector
serializers to count the same recipe emitted by current capture. Empty blobs,
full sectors, tails, lengths and field overhead match current descriptor versions
2/3/4. Sector identity/root bytes have fixed encoded length, so placeholders can
count bytes without creating sector vectors. The existing inclusive 32 MiB
descriptor bound is enforced before publishing candidate metadata or refs.

These checks still assemble and scan the prototype metadata graph in one writer
transaction. They do not provide incremental update scheduling, full enclosing
native/revision admission budgets, or merge/checkout/import/fetch preflights.
Those consumers, oversized-history status/export policy and real capacity
qualification remain required before closing R2 or enabling the production
catalog. No wire versions, control schema or existing history are rewritten.

Six new preflight/transaction fixtures cover dense recipe geometry and exact
boundaries, rejection of a large commit before publication, a valid near-limit
history whose added branch/pin/tag cannot fit, preserved export/reopen, cached
blob geometry after payload loss, conflicting cached lengths, competing writers
and SQL abort/ignore rollback. All 93 ordinary store and 77 ordinary Git tests,
28 ordinary snapshot regressions, all 62 provisioned Git library cases and both
native Git capture/restore and rejected-capture repair pass. Disposable Btrfs
mount/image/loop cleanup is verified. Formatting and strict workspace/all-targets
Clippy pass. Ordinary suites retain 18 ignored store and eight ignored snapshot
cases; these results do not replace the complete M6 release/production gates.

Fetch and stock branch/tag push now preflight the combined destination graph
before recording a fresh intent or creating blob anchors. The reachable
descriptor traversal accepts imported blob lengths before mappings exist;
existing cached lengths must agree. Both source and retained destination history
contribute to the same descriptor limit, rather than testing the source alone.
Replayed intents recheck admission before importing any remaining blobs. A
capacity failure retains their exact intent and prior history for explicit
repair; already captured pending anchors remain owned.

Final publication checks the immutable intent, combined budget and ref/tag
conditions under the same immediate writer transaction that publishes metadata,
refs and deletes temporary verification/intent rows. Push also checks selected
branches, the advertised old ref and fast-forward ancestry there. Ancestry uses
hash-checked proposed objects in a temporary metadata repository, so it does not
need to publish those objects before deciding whether the push is admissible.
Irrecoverable stale/ref/tag conflicts retire only the exact owned intent and its
temporary verification rows using guarded publication. Wire formats and native
anchor verification remain unchanged.

These checks address descriptor growth for fetch and stock push. Signed-backup
reconstruction, merge/checkout, full enclosing native/revision budgets,
oversized-history status/export policy and bounded incremental scheduling remain
open. This is not production admission for the declared 1 TiB target.

Two new fixtures reject individually bounded source/destination histories whose
combined descriptor exceeds 32 MiB before creating intents or anchors; they also
preserve an oversized pending intent and prior history across reopen. Successful
imports reuse existing anchors, publish a valid fast-forward and reject a
divergent push before its metadata is written. All 79 ordinary and 62 provisioned
Git library tests, 28 ordinary snapshot regressions and both native capture
regressions pass, with verified disposable Btrfs mount/image/loop cleanup,
formatting and strict workspace/all-targets Clippy. The ordinary snapshot suite
retains eight ignored provisioned cases; the two named capture tests ran
separately. This is targeted mutation/replay qualification, not the full M6 gate.

Generated merges now build their candidate tree/commit and bounded text blobs
in disposable memory backends before capturing native anchors. Admission counts
the entire prospective reachable graph with generated blob lengths, then checks
branch/HEAD and size again under the metadata publication writer lock. No file
payload is written to a Git object directory. A rejected initial admission
preserves existing history and anchors; subsequent interrupted capture retains
its existing owned journals for replay.

Descriptor sizing now reads the prospective primary HEAD record, including its
name length. Linked-worktree HEAD records do not replace that primary backup
HEAD. Same-tree branch selection checks the current branch, old and target refs,
branch reservations and budget under its publication writer lock. Fresh checkout
checks before publishing an intent; replay checks before staging/moving files.
Final index/HEAD/ref publication and merge-session retirement recheck the exact
journal, branch/target and budget in one writer transaction. Restore formats do
not grow the graph, and cleanup of already-published operations can proceed
without a new descriptor growth restriction. A capacity failure on a pending
checkout preserves its journal for repair. Worktree moves remain replayable;
this SQL publication check does not make filesystem moves transactional.

Four new fixtures exercise proposed HEAD validation, oversized generated merges
before anchor capture, HEAD-name growth at the descriptor boundary, and oversized
checkout replay without staging, including unchanged prior history on reopen.
The full enclosing native/revision contract, signed backup reconstruction,
oversized-history status/export policy, incremental scheduling and end-to-end
capacity qualification remain open. This increment does not enable production
admission or the declared 1 TiB target.

All 83 ordinary and 62 provisioned Git library tests, 28 ordinary snapshot
regressions and both native Git capture/restore and rejected-capture repair pass.
Disposable Btrfs mount/image/loop cleanup is verified; formatting and strict
workspace/all-targets Clippy pass. The targeted admission run also passes both
existing SQL writer/fault fixtures. Eight provisioned snapshot cases remain
ignored in the ordinary suite; the two named capture cases ran separately.
This is targeted mutation/replay qualification, not the complete M6 release gate.

Backup graph reconstruction now rechecks its empty metadata/ref/index/HEAD
destination and anchor-record conflicts under the same writer lock used to
publish object mappings, metadata, refs and the clean index/HEAD. Validation
still checks the descriptor's actual encoded sparse sector recipes and verifies
exact native blob IDs before publication. It does not substitute dense mutation
geometry for a valid recovered legacy descriptor. The caller must authenticate
the enclosing signed revision before this local import API is used.

Two new fixtures inject competing writes into each destination namespace and
anchor mapping before publication, preserve competing state on rejection and
reopen, then recover exact refs, IDs, index and anchor bytes after repair.
Libgit2-valid descriptors immediately below, at and above the inclusive 32 MiB
bound prove exact accepted imports on reopen and unchanged empty rejected
catalogs. Full enclosing admission budgets, oversized-history status/export,
incremental scheduling and production-capacity qualification remain open.

All 85 ordinary Git library tests and 28 ordinary snapshot regressions pass.
Provisioned annotated-tag backup import/reopen and both native capture
regressions pass on disposable Btrfs with verified mount/image/loop cleanup.
Formatting and strict workspace/all-targets Clippy pass. The ordinary suites
retain 62 provisioned Git and eight snapshot cases; the one Git import case
and two capture cases were run separately for this increment.

Primary and linked Git status now expose an optional current-capture descriptor
capacity result. The read-only measurement uses all retained refs/ancestry and
cached blob lengths to count the exact dense recipe shape used by capture, with
an inclusive 32 MiB bound. Missing/incompatible graph mappings produce an
unavailable result. The result is independent of certified backup protection;
a fitting descriptor does not certify native metadata, signed revision or
payload availability. Older local-control status responses still decode.

Oversized native history can be preserved with `mutualgit export` into an
existing empty SHA-1 bare Git repository outside primary/linked source roots.
Export includes all retained refs, remote-tracking refs and pins, exact raw
objects and blobs, plus the primary symbolic HEAD. It uses the existing verified
anchor streaming path without applying the backup descriptor bound; prototype
graph traversal bounds still apply. Populated destinations are rejected. All
known destination refs are locked before objects are written, but libgit2's
filesystem ref publication can fail partway through. Such a failure reports an
error and keeps the source intact; use a fresh empty destination to retry. This
export covers committed native history and does not convert withdrawn FUSE state,
copy uncommitted bytes, remove protections or enable production paged migration.

New fixtures cover oversized status and full export with every retained ref
namespace, byte-exact metadata/blobs, stock Git strict fsck, populated/inside-root
and locked-destination rejection, unavailable graph mappings, and reopen.
Existing import-boundary fixtures now check exact capacity immediately below and
at the descriptor limit. Schema tests cover each capacity state and omitted
legacy status fields; CLI tests cover capacity wording and the concrete export
remedy. A provisioned daemon/CLI fixture exercises raw non-UTF-8 file and
export-destination paths with remote refs, tags, pins and byte-exact export.
Full enclosing R2 budgets, bounded scheduling and end-to-end R3 capacity remain
open; this status/export increment does not support the 1 TiB release target.

All 87 ordinary and 62 provisioned Git library tests, 28 ordinary snapshot
regressions, seven mutualgit unit tests and the expanded local-wire schema
fixture pass. The real daemon/CLI raw-path fixture passes full export of remote
refs, tags, pins and non-UTF-8 paths with exact bytes and stock Git strict fsck.
Both native capture regressions pass. Disposable Btrfs mount/image/loop cleanup,
formatting and strict workspace/all-targets Clippy are verified. The ordinary
snapshot suite retains eight provisioned cases; the two capture cases ran
separately. This does not replace the complete M6 release gates.

Private catalog pages now have a live local-sector source adapter. The append-only
`CatalogPage` source variant stores scope, section and an authenticated page
reference, preserving the existing source discriminants. Node staging verifies
owner/scope/section and page before deriving the private sector ID, ciphertext
root and Merkle commitment. Its recipe is at most 1 KiB and references SQLCipher
page storage rather than duplicating the plaintext as an Inline source. The live
sector renderer regenerates the exact existing 64 KiB information-sector bytes
and rejects source ID/length, owner/guild or page substitution before use.

A dedicated one-page catalog intent publishes its exact local-sector recipe,
root pin and immutable ownership link in one writer transaction. An active
source pin cannot be cancelled independently or linked to a descriptor bundle;
its lifecycle follows that exact local recipe. Its root retains the page closure
even when original builder ownership is cancelled. A durable indexed cursor
visits one source pin per step, comparing a potentially larger replacement
recipe in SQLite without allocating it. Once the owner record is deleted or
replaced, one transaction fences the old intent and releases its pin; stale
writers cannot resurrect its cancelled ID. SQL ignore faults roll back the whole
publication or release. Checkpoint cleanup schedules one pin visit and one
bounded page collection step. Pending cancelled IDs still require a future
verified generation floor before tombstone retirement.

Five new fixtures cover shared-page closure, publication/retirement reopen,
bounded cursor work, injected SQL ignore failures, live Node rendering with
identical IDs/roots/commitments across reopen, owner/guild/reference/page
substitution and legacy Inline bytes. This adapter does not authenticate a
signed revision, enable a paged capture format or qualify 1 TiB capacity.
Capture/admission, packing/coding, retention and seed-only recovery still need
consumer migration. Existing signed revision/private metadata formats and bounds
remain; withdrawn private metadata 6/7 are not reinterpreted.

All 96 core, 96 ordinary store, 87 ordinary Git, 362 ordinary Node and 16
CLI-library tests pass. All 62 provisioned Git and all eight provisioned
snapshot regressions pass on disposable Btrfs with verified mount/image/loop
cleanup. Formatting and strict workspace/all-targets Clippy pass. The ordinary
suites retain 18 store, 62 Git and 20 Node provisioned cases; the Git and snapshot
cases above ran separately. This source integration and legacy regression
qualification does not replace the complete M6 production gates.

### Authenticated range traversal (2026-10-06)

`CatalogRangeReader` reads an exact byte range using the existing version-one
page tree. It authenticates intersecting parents and leaves, deriving skipped
subtree offsets from verified parent summaries. It preserves offsets for
repeated page occurrences and visits no preceding leaves. Returned chunks stay
within one bounded leaf; pending references stay within the existing fanout and
height bound. Invalid ranges fail at construction, empty ranges fetch nothing,
and any storage or verification failure permanently poisons that reader.

This operation authenticates the requested range. It does not certify the
integrity or availability of skipped pages, replace whole-stream validation,
or provide signed root authority. Callers still obtain roots from authenticated
metadata and bound fetched page allocation. Page geometry and wire formats are
unchanged. Stable typed-record locations, variable-length editing and production
consumer migration remain required before bounded byte seeking makes capture,
restore and small edits incremental end to end.

Three core fixtures cover combinations of leaf boundaries and partial leaves,
small reads at every tree level and at the exact 16 GiB stream limit, repeated
subtrees, invalid ranges, storage failures, corruption and reference/scope
substitution. The maximum-size fixture constructs a repeated tree rather than
allocating 16 GiB or qualifying real 1 TiB dataset data. A reopened SQLCipher
fixture reads the tail in two page fetches while an unrelated first leaf is
corrupt; full traversal rejects that corrupt leaf and the published root stays
pinned across reopen. All 99 core and 97 ordinary store tests pass, with 18
provisioned store cases still ignored, plus formatting and strict workspace/
all-targets Clippy. Native source-backend and topology qualification were not
rerun for this reader addition. R3 and the full M6 release gates remain open.

### Path-copying splices and durable successors (2026-10-06)

`CatalogPageRef::splice` replaces an authenticated byte range with at most one
60 KiB leaf of replacement bytes. It supports insertion and deletion without
repaging the untouched suffix. Only boundary paths are fetched; deleted
subtrees are skipped using authenticated summaries. New pages are emitted
child first, while untouched subtrees keep their addresses. Repeated page
occurrences remain independent through their stream offsets. Equal edits do
not emit unchanged pages. An empty no-op returns the original root directly.

The edit retains bounded leaf buffers and at most fanout-plus-one references
per active height. Index overflow splits parents and may grow the root.
Stream, occurrence and height bounds remain mandatory. Excessively fragmented
trees can require rebalancing before a growing edit fits; this operation fails
rather than producing an out-of-format tree. General rebalancing/compaction,
stable typed-record indexing, typed validation and multi-edit scheduling remain
open. A byte splice does not certify the meaning of a record stream, validate
skipped pages or supply root authority.

`ControlStore::stage_catalog_splice` uses a Building successor intent and the
existing child-first page/link transactions. Even an unchanged result acquires
successor root ownership before returning. The caller holds the original root
pinned until successor staging completes. Publication is explicit and separate.
An interrupted or failed edit may leave pending pages, which remain available
for deterministic retry or cancellation; no failed edit returns a publishable
root. Published and cancelled intent fences continue to reject later staging.

Five core fixtures cover boundary combinations, insertion/deletion/replacement,
parent splitting, repeated occurrences, no-op writes, storage/corruption faults,
stream/height limits and original-root preservation. Small edits and deletion
of nearly the entire exact 16 GiB catalog stream fetch at most two boundary
paths. That fixture uses a repeated authenticated tree, not real 1 TiB dataset
data. Two reopened SQLCipher fixtures cover successor publication/cancellation,
shared-closure reclamation and retry after a parent INSERT failure with new
leaves already durable. All 104 core and 99 ordinary store tests pass, retaining
18 ignored provisioned store cases, plus formatting and strict workspace/
all-targets Clippy. Native source-backend and topology gates were not rerun for
this API addition. Quota admission, signed paged revisions and production
capture/packing/replay/retention/recovery migration remain required; R3 and M6
are still open.

### Repair page payloads while retaining source ownership (2026-10-06)

The shared recovered information-sector installer now recognizes an active
private catalog source before considering Inline fallback. The bounded source
descriptor comes from the exact live recipe and its published page pin. Node
checks the recovered sector reference and recipe bytes, dataset guild/owner,
scope/section, keyed private address, ciphertext root, padding and canonical
page. It then restores the authenticated page payload rather than replacing
the recipe with Inline bytes and leaving the page tree damaged.

The SQLCipher repair transaction rechecks the exact recipe and published
ownership, immutable page metadata and immediate child links under a writer
lock. It changes only the bounded payload, including reinserting a missing
payload when ownership and metadata remain intact. A parent's payload can be
repaired before a missing descendant payload: existing authenticated child
metadata and links are required, but each descendant's payload is independently
verified and repaired. Missing/damaged ownership metadata or links are not
reconstructed by this operation. Recipe replacement/deletion or source
retirement rejects stale page repairs. Affected-row checks reject SQL IGNORE
faults. The repaired source keeps its original recipe, pin and encrypted sector
identity; ordinary cleanup continues to retain its closure.

Two store fixtures cover oversized corrupt and missing payloads, reopened
ownership, stale recipe snapshots, SQL ignore rollback and retired intent
fences. Two live Node fixtures cover independent parent/child repair and reopen
with exact recipe bytes, ciphertext and Merkle commitments, plus guild/reference/
ciphertext substitution. This extends local repair under existing source
ownership. It does not recover page descriptors/pins from an empty control
store, establish signed paged revision authority or migrate normal capture,
packing/checkpoint/retention and seed-only recovery. Those R3 gates and the real
1 TiB dataset qualification remain open.

Validation for this repair step: all 104 core, 101 ordinary store, 364 ordinary
Node and 16 CLI-library tests pass. All eight provisioned snapshot regressions
pass on disposable Btrfs, including native/Git source-loss reanchoring, with
verified mount/image/loop cleanup. Formatting and strict workspace/all-targets
Clippy pass. Ordinary suites retain 18 store and 20 Node provisioned cases; the
eight snapshot cases ran separately. Full paged seed-only recovery and the M6
topology/platform release gates remain unqualified.

### Current flat capture data-sector admission (2026-10-06)

Prospective Git mutation admission now also applies the existing flat capture's
39,488 data-sector limit. Both capture and Git admission use the shared core
constants reserving 512 metadata positions out of 40,000 coding positions. Dense
recipe geometry rounds each unique graph blob independently to 64 KiB references,
including its final partial sector and excluding empty blobs. This conservative
estimate assumes distinct sector identities: capture can deduplicate identical
Git sectors, but cached lengths do not prove their sharing. It is neither
physical allocation nor sparse/shared payload accounting for the production target.

Previously a Git graph with more than 39,488 distinct dense references could fit
in its 32 MiB descriptor and publish, then fail capture at the separate data-vector
limit. The common prospective graph preflight now bounds dense geometry before
publication; current status names the data-sector limit and keeps the stock Git
export remedy. Imported lengths participate before anchor creation. Existing
history remains readable and recovery/import keeps its authenticated sparse
recipe policy. The full enclosing private/revision budget and paged capture
pipeline remain required; this interim admission check does not enable 1 TiB.

### Signed paged revision envelope (2026-10-06)

`PagedUserRevision` in `mb-core` supplies bounded signed authority for the
migration pipeline. Format 8 replaces flat source/commitment vectors with one
typed public source root and an exact encrypted bootstrap-sector record. The
complete signed record is bounded to 2 KiB. Owner and current-writer signatures
are counted together before either signing operation. A shared 8 KiB bootstrap
limit applies in both core envelope admission and the Node private decoder.
The immutable `paged-user-revision-v8.postcard.hex` vector records exact field
order, signatures and domains for a deterministic fixture. The signatures
bind all identities, sequence/parent and both roots, using distinct paged
signature/hash domains. Signature decoding caps both collections at 64 bytes
before allocation; canonical encoding and supported versions remain mandatory.
Existing flat revision formats 3–5 and withdrawn private formats 6/7 retain
their original bytes and interpretation.

`PagedRevisionSourceReader` requires the expected guild/owner and checkpoint's
certified writer fence. It verifies source pages in sector-ID order and requires
an exact bootstrap reference/commitment match. Completion is false until the
authenticated end of the whole source stream; a missing bootstrap, substituted
commitment, corrupt or unavailable tail fails and fences continuation. The
writer fence still requires checkpoint authorization by its caller.

`PagedPrivateMetadata` in `mb-node` is an owner-encrypted format-8 bootstrap
descriptor, bounded to 8 KiB, containing typed native namespace/recipe roots and
optional Git ref/object/blob roots. The private forest shares the existing
aggregate stream/page-occurrence bounds. Private plaintext hashes remain in
encrypted metadata. Opening verifies signatures, both ciphertext commitments,
canonical padding, descriptor geometry and its scoped keyed content address.
This authenticates root authority; it does not prove that every private page or
file/blob recipe joins the signed sources, or publish durable root ownership.

The codec is available for consumer migration; ordinary capture, checkpoint,
packing, retention and seed-only recovery remain on existing formats. Their
migration, shared retained-history quota and real 1 TiB qualification are required
before production admission is enabled. No format-8 protection claim is emitted
by ordinary backup yet.

Validation: five core and three Node fixtures pass, covering immutable signed
bytes, signature/root/identity substitution, oversized signature declarations,
inclusive shared bootstrap geometry, fence and exact source joins, unavailable/
corrupt tails, encrypted native/Git descriptors, both commitments, scoped
addresses, padding and aggregate structural bounds. All 109 core, 30 ordinary
snapshot, five native adapter, six paged Git and 24 catalog-store tests pass
(177 distinct cases including the three new Node fixtures). The new cases and
complete core suite pass again after final admission hardening. Locked workspace/
all-targets build, formatting and strict Clippy pass. Eight provisioned snapshot
cases remain ignored; no full native/topology/platform or real 1 TiB gate ran.

### Durable signed paged root publication (2026-10-06)

`PagedPrivateMetadata::publish_local_catalog` connects the signed envelope to
local SQLCipher ownership. It retains native namespace/recipe and public source
roots, plus optional Git ref/object/blob roots, in explicit role order. These
three or six roots share the existing aggregate stream/page-occurrence bound.
The completed native/source validation index is bound to the same revision ID.
An immutable encrypted bootstrap sector, saved signed migration record and
bootstrap-owner pin publish in the same writer transaction as every root pin.
The new namespaces leave current flat revision heads and protection unchanged.

`CatalogPublicationView` provides reads from that exact writer snapshot without
nested transactions. Node checks the supplied certified writer fence, signed
source EOF and bootstrap identity, exact source-index records, every private
page's derived ciphertext reference/Merkle commitment, typed Git stream EOFs
and blob recipe/source joins. Reopening compares the decrypted descriptor with
all retained roots and checks the signed record, native index and bootstrap
ownership together. Subsequent traversals still authenticate actual bytes.

Typed cancellation fences the validation index and all member intents in one
transaction before releasing the signed migration record and bootstrap pin.
Shared bootstrap ciphertext survives until its last revision owner retires.
Independent bundle/member/index cancellation is rejected while published.
Existing bounded index/pin/page cleanup APIs reclaim cancelled closures;
cancellation journals remain until generation-floor retirement is implemented.
SQL abort/ignore faults must roll back the complete publication or cancellation.

This is durable migration-root ownership. It does not install file/blob source
recipes, advance a production backup head, establish checkpoint/remote protection,
verify the complete Git DAG or plaintext blob IDs, or qualify the 1 TiB target.
Normal capture, checkpoint/packing, retention and seed-only recovery consumers
still need to adopt the roots and complete those activation checks together.

Validation: three new store and two Node fixtures pass, with SQL abort/ignore
faults across publication/retirement boundaries, shared bootstrap ownership,
reopen/retry and independent cancellation fences. Native/Git-bearing fixtures
exercise raw paths, sparse recipes and forward hard-link identity. Rejected
writer authority creates no validation rows; missing/substituted page/bootstrap
sources and mismatched Git recipes leave no published root or bootstrap.
All 109 core, 111 ordinary store, 30 ordinary snapshot, five native adapter,
six paged Git and five paged Node tests pass (266 distinct cases). The five Node
cases pass again after early writer-fence admission was tightened. Locked
workspace/all-targets build, formatting and strict Clippy pass. Nineteen
provisioned store and eight snapshot cases remain ignored; no native/topology/
platform or real 1 TiB gate ran for this local ownership step.

### Live bootstrap sector rendering (2026-10-06)

`paged_revision_bootstrap_catalog` resolves one owner using the sector's indexed
bootstrap-pin namespace. The read transaction checks the pin's bounded key/value,
published signed revision, exact requested bootstrap ID, retained member roots,
native validation index and ciphertext commitments. A pin without a valid live
owner or ciphertext without a pin is an integrity error. It does not scan retained
history or allocate a source list. A corrupt selected owner fails the lookup;
another owner is not used to hide damaged ownership state.

The ordinary local sector renderer consults this ownership before legacy recipes.
Node authenticates the seed/guild, decrypts and validates the private descriptor,
and compares all root roles with the retained bundle using that same snapshot.
The returned ciphertext remains owned by the paged publication; no independently
collected Inline copy is installed. Shared bootstrap owners retain availability
through individual cancellation, and the last owner's cancellation removes the
source. A concurrent read may finish using the snapshot acquired before retirement.

Private page/file/blob source integration, normal capture/checkpoint/packing,
retention and seed-only recovery migration remain open. This source adapter
neither advances a flat head nor establishes production protection or 1 TiB support.

Validation: two new store fixtures and one Node fixture cover shared-owner
retirement and reopen, malformed/oversized pins, orphaned sources, cancelled or
substituted owner identity, ciphertext damage, wrong seed/guild and legacy recipe
precedence. Node exercises both native-only and Git-bearing roots. Locked
workspace/all-targets build and 22 paged tests pass, alongside 113 ordinary store,
30 ordinary snapshot and five native adapter tests (165 distinct cases overall).
Formatting and strict locked workspace/all-targets Clippy pass. Nineteen
provisioned store and eight snapshot cases remain ignored; native/topology/
platform and real 1 TiB qualification were not run for this adapter step.

### Revision-owned private page sources (2026-10-06)

Publication now binds each private index/leaf page to its encrypted sector through
`CatalogPublicationView::bind_private_page_source`. These derived rows are keyed
by revision and sector and publish or roll back with all root pins. The binding
checks private member intent ownership, immutable page metadata and exact signed
source-index identity. Node creates bindings during authenticated root traversal,
after deriving each ciphertext reference and Merkle commitment. Identical pages
under multiple member roots retain one verified member owner and one sector row.

`render_local_catalog_page` requires the retained revision and expected dataset
scope explicitly. A bounded indexed lookup checks publication, encrypted private
descriptor/root roles, member ownership and source identity, reads authenticated
page bytes in that database snapshot, then regenerates ciphertext and checks both
signed commitments. This avoids scanning retained history to find a sector owner
and avoids separate legacy Inline or dedicated page-source intent lifetimes.

`repair_local_catalog_page` authenticates recovered ciphertext and decodes its
scoped page. Under the writer, repair checks the exact live source snapshot,
immutable metadata and index-child links before updating only the page payload.
The source descriptor remains readable without payload bytes so missing/corrupt
pages can be repaired. Cancellation immediately fences source reads and repair;
`release_paged_revision_page_source` later deletes one derived row per transaction.
Shared revisions retain their own bindings and root pins independently.

The adapter is deliberately revision-scoped: ordinary ID-only source serving,
stable file/blob sources, native capture/restore, legacy conversion, checkpoint/
packing/retention and seed-only recovery activation still require integration.
It does not advance production heads or qualify the declared 1 TiB target.

Validation: two new store fixtures cover shared-page deduplication, shared
revision ownership, reopen, missing payload repair, cancellation between read
and writer repair, bounded cleanup, oversized bindings and SQL abort/ignore
faults. One Node fixture adds 1,000 directories to force index pages and checks
native-only and Git-bearing private root regeneration/repair, corrupt payloads
and ciphertext, wrong seed/scope, cancellation and exact one-row cleanup counts.
Locked workspace/all-targets build and 25 paged tests pass, alongside 115 ordinary
store, 30 ordinary snapshot and five native adapter tests (168 distinct cases
overall). Formatting and strict locked workspace/all-targets Clippy pass.
Nineteen provisioned store and eight snapshot cases remain ignored; native/
topology/platform and real 1 TiB qualification were not run for this step.

### Stable native/Git data sources (2026-10-06)

`publish_local_catalog_with_data_sources` accepts a provider called for each
authenticated signed sector. Supplied `PagedAnchorSectorSource` recipes identify
a stable anchor file and offset, with an 8 KiB encoded recipe limit. Before
binding, Node checks dataset ownership, nonempty sector geometry, overflow and
file bounds; it opens the existing stable locator, reads at most one 64 KiB
sector and verifies the scoped Data content address, encrypted reference and
Merkle commitment. It never assembles a dataset-wide recipe or payload vector.

Derived source rows are keyed by revision/sector. Store checks the completed
source index and retains a physical anchor count atomically with each new row,
all root pins and the signed revision. Exact retries do not increase counts.
Bootstrap sources cannot be installed as data recipes. The low-level binding
trusts the caller to authenticate its opaque recipe; the Node facade does so.
`render_local_data_sector` checks a single database ownership snapshot, expected
scope, signed/private descriptor and canonical recipe/anchor identity, then
regenerates and rechecks the exact file range and signed commitments.

Cancellation immediately disables reads but retains physical anchor pins until
`release_paged_revision_data_source` deletes one cancelled recipe and decrements
its anchor count in one writer transaction. Other sectors/revisions keep their
counts. Native anchor retirement and retirement replay reject retained pins;
existing native Git prune includes their identities through its compatibility
collection. That legacy bridge still materializes an anchor-identity set, while
source reads and per-source cleanup stay bounded. This does not complete the
production prune/retention consumer migration or concurrent filesystem lifecycle
qualification.

Validation: two new store fixtures check shared anchor retention across reopen,
cancellation, exact retry and SQL abort/ignore source/pin insertion/deletion
faults. Two new Node fixtures use marked local anchor areas with native and
Git-bearing roots, checking source regeneration, byte changes/loss, wrong
seed/scope, overflow, unsafe/oversized paths, prune-pin visibility and bounded
cleanup. These are adapter tests, not native capture qualification. Locked
workspace/all-targets build and 29 paged tests pass, alongside 117 ordinary store,
30 ordinary snapshot and five native adapter tests (172 distinct cases overall).
Formatting and strict locked workspace/all-targets Clippy pass. Nineteen
provisioned store and eight snapshot cases remain ignored; native capture/
topology/platform and real 1 TiB qualification were not run for this step.

The provider may omit sources for pending migration roots; publication still
makes no complete capture/protection claim. The adapter uses the existing Linux
stable locator backend. Complete-source capture, Git blob plaintext IDs/full DAG
verification, retained-history conversion, checkpoint/packing, production
retention and seed-only recovery activation remain open, as does real 1 TiB
qualification.

### Conditional stable-source recovery replacement (2026-10-06)

`replace_local_data_source` accepts an observed retained source and replacement
stable anchor range. It bounds the encoded recipe and authenticates seed/scope;
the store writer then rechecks the complete signed/root snapshot, exact source
and local generation before Node regenerates the replacement bytes and verifies
the scoped Data address and both signed ciphertext commitments. Source update,
new anchor retention and old anchor release commit together. Shared owners retain
their counts; changing only a range within one anchor does not change pin counts.

Derived binding codec version 2 adds a monotonic `u64` generation. Canonical
version-1 rows read as generation zero and exact publication retries preserve
their original bytes. Changed recipes advance the generation; exhaustion fails
before publication. Returning to identical old recipe bytes cannot restore an
older attempt's authority. An exact retry is accepted only at the immediately
following generation with identical replacement bytes, and still reauthenticates
the physical source. A no-op at the current generation likewise verifies bytes.
Cancelled roots cannot be rebound. Signed revision/private codecs stay unchanged.

This is conditional local source replacement, not a cold-recovery activation.
Complete capture and seed-only recovery, filesystem/source-intent concurrency,
retention/prune migration, legacy conversion and real 1 TiB qualification remain
open.

Validation: three new store fixtures cover rejected authentication, shared pin
transfer, same-anchor range changes, exact retry, stale/competing/cancelled
attempts, return to an old recipe, canonical legacy bytes and generation
exhaustion. SQL abort/ignore faults cover source update, new pin insert/update
and old pin update/delete. One Node fixture exercises native and Git-bearing
roots with lost sources, corrupt replacements, retry reauthentication, reopen,
competing attempts and cleanup. Locked workspace/all-targets build and 33 paged
tests pass, alongside 120 ordinary store, 30 ordinary snapshot and five native
adapter tests (176 distinct cases overall). Formatting and strict locked
workspace/all-targets Clippy pass. Nineteen provisioned store and eight snapshot
cases remain ignored; native capture/topology/platform and real 1 TiB
qualification were not run for this local operation.

### Whole legacy private conversion (2026-10-06)

`convert_legacy_revision` connects native namespace/recipes and optional Git
refs/objects/blobs to one authenticated legacy input. It bounds the original
signed envelope and private payload before signature work, checks recovering
seed/guild, owner/writer signatures, dataset identity and sequence shape, then
verifies metadata ciphertext roots and available Merkle commitments. Private
encodings and metadata padding must be exact. The strict conversion decoder
supports native formats 1/3, both frozen version-2 layouts and Git-bearing 4/5;
normal legacy recovery decoding remains unchanged. Withdrawn 6/7 are rejected.

Every native/Git sector reference must match signed legacy data exactly. All
signed data, including unused retained references, is read and checked against
its ciphertext root and available Merkle commitment. Legacy Git validation checks
the graph/object schema; blob plaintext is streamed through sparse extents and
zero holes and verified against its raw Git SHA-1 object ID. The new
`GitBackupBlob::verify_plaintext` uses one sector-sized buffer, requires exact
logical length/EOF and propagates read errors. Hash work includes logical holes.

Both typed adapters and their aggregate root geometry preflight before calling
the external page sink. Separate explicit stream roles preserve durable intent
ownership. Sink failures leave staged pages under the caller's intents for
normal retry/cancellation and return no complete root. Original data addresses,
native attributes/recipes/hard links and raw Git object/ref identities remain
unchanged; this function does not update old signed revisions or heads, sign a
new revision, or publish protection.

The Linux conversion adapter still reads an old bounded flat metadata object;
it does not establish the new dataset/history capacity. Old non-content-derived
sector addresses need a compatible authenticated source path or rewrite policy
before consumer activation. New source authority/publication, native capture/
restore, retention, seed-only recovery, full filesystem/platform qualification
and the real 1 TiB gate remain open.

Validation: one new Git fixture checks bounded blob hashing, exact length/EOF,
wrong bytes and I/O errors. Four new Node fixtures cover private formats 1/3/4/5,
both frozen version-2 layouts, signed outer 3/4/5, exact Git refs/object bytes,
sparse blobs/hard links, source/commitment/authority/schema substitutions,
withdrawn formats, original/head preservation, reopen/native source validation
and sink interruption with intent cleanup. Locked workspace/all-targets build
and 38 paged tests pass. All 90 ordinary Git, 120 ordinary store, 30 ordinary
snapshot and five native adapter tests also pass (264 distinct cases overall,
including five paged core and 14 paged Node cases). The four conversion cases
pass again after test-only lint fixes. Final formatting and strict locked
workspace/all-targets Clippy pass. Sixty-two provisioned Git, 19 store and eight
snapshot cases remain ignored; native capture/topology/platform and real 1 TiB
qualification were not run for this conversion adapter.

### Historical data source addresses (2026-10-06)

`PagedLegacyDataAuthority` bounds the old signed envelope/private geometry and
verifies recovering seed/guild, owner and writer signatures, dataset identity,
sequence shape, data ranges, optional commitment alignment, duplicate reference
consistency and separation from metadata IDs. It holds a bounded membership
index and creates opaque `PagedDataSource` values only for exact signed data
references and available old commitments. This source authority does not approve
an old private schema; the complete conversion adapter still rejects withdrawn
private formats 6/7 before producing native/Git roots.

`publish_local_catalog_with_authenticated_sources` accepts these explicit
historical sources alongside scoped content sources. Under the existing atomic
publication writer, it checks the dataset and exact signed new source, reads one
bounded anchor range and verifies both the ciphertext reference and Merkle
commitment using the original ID. Historical format-3 sources acquire a verified
Merkle commitment in the new signed source catalog. Ordinary source publication
still requires the scoped Data content address and never falls back after an
address mismatch. The newly signed paged source root supplies authority after
reopen; the old revision hash retained in the local recipe records provenance,
not an independently replayable signature proof. Original signed revisions and
heads remain intact for recovery/audit and later migration policy.

The canonical historical local recipe has an explicit version and retains its
dataset, exact source and original revision identity. Existing two-field scoped
recipes keep their bytes and semantics. Decoder dispatch is unambiguous: the old
recipe starts with a UUID byte-string length of 16, the historical recipe with
version 1. Both require exact bounded canonical bytes; unknown versions,
truncation, trailing bytes and overlong encodings fail without fallback.
Replacement preserves the existing address policy, reauthenticates bytes under
the publication/generation fence and transfers anchor pins atomically. It cannot
turn a scoped binding into a historical one. Cancellation stops serving before
bounded source cleanup releases physical retention.

This completes local stable-source compatibility for converted legacy roots.
It does not automate retained-history conversion/publication, activate normal
capture/restore or checkpoint/seed-only replay, qualify filesystem lifecycle,
or establish the declared 1 TiB dataset/history capacity.

Validation: three new Node fixtures cover frozen scoped recipe bytes; unknown,
truncated, trailing, overlong and oversized local encodings; signed historical
membership and source/commitment/authority/geometry substitutions; and complete
native-only plus Git-bearing conversion/publication with original ciphertext
IDs. They exercise strict normal-address rejection, damaged-source rollback,
publication/replacement retry, seed/dataset checks, reopen, lost-source recovery,
generation and pin transfer, original/head preservation and cancellation/cleanup.
Locked workspace/all-targets build and all 41 paged tests pass (five core, seven
Git, 17 Node, 12 store). Thirty ordinary snapshot/restore and five native adapter
tests also pass, for 76 distinct cases. Formatting and strict locked workspace/
all-targets Clippy pass. Eight provisioned snapshot cases remain ignored; full
native capture/topology/platform, filesystem lifecycle and real 1 TiB
qualification were not run for this source adapter.

### Ordinary sector serving and owned-page recovery (2026-10-07)

The ordinary sector renderer now routes paged bootstrap, private-page and
native/Git data requests through retained root ownership before legacy recipes.
`paged_sector_source` selects existing source rows by sector ID using a partial
covering database index on `(record_id, kind)`. No duplicate source-owner journal
or revision-history collection is introduced. Each candidate's complete signed
root/source/pin state is checked in a read snapshot. Page rendering rechecks its
immutable owner and payload together; data rendering retains its scoped or
authenticated historical address policy and exact ciphertext commitments.
Wrong seed/guild, malformed or orphaned rows and damaged selected live sources
fail closed instead of using an independent legacy copy.
Missing current-schema indexes also fail closed; only known read-only older
schemas retain the pre-upgrade absence of automatic source lookup.

Cancelled source rows remain owned until existing bounded cleanup. Lookup skips
only valid cancellation journals and checks at most 64 candidates plus one
bounded next-key/EOF query. Excess retired-owner backlog returns an explicit
cleanup/retry error. It cannot turn budget exhaustion into authenticated absence
or a legacy fallback. Background cleanup and generation-floor policy still need
production integration before this limit can be qualified on retained history.

Database schema 10 transactionally installs the exact partial-index definition
over existing source bindings; old rows need no conversion or ownership replay.
Known older control schemas migrate through the normal writer. Read-only old
catalogs retain their exact schema and explicit-revision source APIs; automatic
paged lookup becomes available after writable migration. Exact schema validation
also checks approved index type, columns and predicate and rejects substitution.
The global parity schema advances from 9 without changing shard or reservation
tables, preserving live reservations and checking volume identity first. Control
migration and this parity upgrade check metadata affected-row counts, rolling
back SQL abort/ignore rather than committing partially relabeled state. Initial
index construction is one transactional catalog scan; large-catalog upgrade
cost/interruption remains part of release qualification.

The recovered information-sector installer resolves paged ownership before
legacy page or Inline recipes. It verifies the expected signed reference,
Merkle commitment, seed/guild and private root authority, then repairs private
page payloads through the existing exact-owner writer transaction. Native and
Git private roles, including index pages, keep their root pins and source bytes.
Matching live data needs no replacement; scoped paged-only lost/damaged data
must use the existing stable-anchor replacement API and cannot acquire an
independent Inline lifetime. The historical migration coexistence correction
below permits the original flat recovery recipe while native ownership is rebuilt.
Complete data recovery orchestration, native capture/restore, full paged Git DAG
verification, checkpoint/packing/retention and seed-only activation remain open,
as do filesystem/platform and real 1 TiB dataset/history qualification.

Validation: five new store and one Node fixtures cover exact indexed query
plans, schema-9 source migration/read-only preservation, metadata abort/ignore
rollback, index substitution/loss, parity reservations and volume identity,
shared live owners, malformed/orphaned/damaged rows and the 64-owner work/EOF
boundary with cleanup. Ordinary serving and recovery exercise native/Git private
roles and index pages, stable data, wrong seed/guild/source/ciphertext, Inline
fallback fencing, reopen and cancellation. Historical-address conversion also
checks the ordinary renderer. Locked workspace/all-targets build and all 47
paged tests pass. Full ordinary suites pass 109 core, 90 Git, 404 Node, 125 store
and 33 CLI unit tests, for 761 distinct cases including the paged tests. Node ran
with four test threads and completed in 1406.42 seconds; no observation timeout
was treated as failure or used to restart the process. Formatting and strict
locked workspace/all-targets Clippy pass. Sixty-two Git, 20 Node and 19 store
provisioned tests remain ignored. Full native capture/topology/platform,
filesystem lifecycle and real 1 TiB qualification were not run for this source
routing integration; this is not current release-artifact R7 qualification.

### Legacy parity upgrade metadata fence (2026-10-07)

The final version update in parity migrations from schemas 2/3/5/6/7/8 now
requires exactly one affected row, matching the schema-9 upgrade fence. An
ignored write previously could commit converted tables/reservation state while
leaving the old schema version. Rejection now returns a conflict before commit,
rolling back all schema/data changes and retaining the exact old catalog for
safe reopen/retry. This hardens the existing upgrade paths without changing
their accepted versions, shard identities or successful conversion semantics.

One new fixture injects SQL abort/ignore at all six older versions. It checks
the old exact schema and version after failure, unchanged shard bytes and
successful reopen with authenticated READY reads. All 15 targeted parity tests
pass, including the schema-9 reservation/volume identity fixture, existing
upgrade checks and read-only inspection of every known parity schema. Formatting
and strict locked workspace/all-targets Clippy pass. The preceding serving
commit records the full 761-case ordinary run; this focused follow-up does not
rerun those unrelated suites or establish current R7/platform/1 TiB evidence.

### Bounded process-local anchor discovery (2026-10-07)

Linux relocation lookup now keeps an incremental cursor for each area/filesystem/
volume-root key. The global index lock covers only bounded map operations;
filesystem reads and cursor disposal occur outside it. A busy area's per-cursor
lock returns an explicit pending error, allowing unrelated lookups to proceed.
Each request advances at most 2,048 scan steps with a cooperative 25 ms deadline.
This bounds scheduled work, not the duration of an individual kernel I/O call.
Pending work and resource-limit errors never populate the negative cache.

The index holds at most 32 entries. Inactive entries may be evicted, releasing
cursor handles outside the index lock. Streaming directory enumeration uses
pinned descriptor-relative child opens rather than WalkDir's directory buffering.
At most 64 frames are retained across all cursors, each owning a pinned directory
and an iterator; depth is also capped at 64. Paths are bounded at 4,096 bytes,
mount input at 256 KiB and discovery roots at 256. Exhaustion returns an explicit
location-required error. These are local discovery limits, not a new dataset
capacity or supported capture geometry claim.

Scans reject symlinks and mount crossings and check each pinned child's actual
stable filesystem identity, including Btrfs subvolume identity. They keep the
existing ordered-root policy and reject distinct accessible matching areas within
the selected root. A candidate is returned only after that root completes and its
path still resolves to the same native directory and marker. Existing explicit/
catalog hints remain the fast path. Already native-bound Git catalogs preserve
unavailable copies for repair; unbound catalogs fail with the preservation error
before any binding migration. Wire locator encodings remain unchanged.

Five new fixtures exercise incremental wide-directory progress, late duplicate
markers, absent sources, symlinks, stale roots, wrong filesystem identity, exact
candidate/EOF budgeting, depth/path/mount limits, busy-area independence, cached
resolution and candidate replacement. The ordinary store suite passes 131 tests;
the final child-identity check additionally passes all 30 ordinary anchor tests.
The Git suite passes 90 ordinary tests, including unavailable-provenance database
preservation. Node passes 18 paged, five anchor and one reader-capacity tests.
Formatting, diff checks and strict locked workspace/all-targets Clippy pass on
Rust 1.99. The reader permit counter uses equivalent compare-exchange operations
to preserve the Rust 1.91 minimum; a redundant legacy-export closure borrow also
needed removal under the newer Clippy. The workspace/all-targets test build passed
before the final child-identity check; final anchor tests and Clippy compile that
check. Nineteen store, 62 Git and three selected Node provisioned tests remain
ignored. No physical Btrfs/remount, topology, platform or 1 TiB qualification ran.

This completes bounded process-local discovery, not production relocation.
Persisted hints for paged sources, restart/eviction-safe scan progress, operational
retry/recovery integration and physical absent/moved/remount/source-loss gates
remain open. Repeated short-lived commands can currently restart a long scan;
valid durable hints avoid discovery, but the cursor itself is not durable. The
first-release capacity target remains 1 TiB per dataset including retained history,
subject to real-data qualification before production admission.

### Durable paged source location hints (2026-10-07)

Retained paged data rendering now consults the existing `anchor-area-location`
records before relocation discovery. Ordinary sector serving remembers the
resolved raw path only after dataset/root authority, the selected address policy,
exact sector reference and Merkle commitment have all passed. The explicit
revision/data read API remains nonmutating. The ordinary renderer's read-only
flag now propagates through paged routing, so a read-only control catalog can
consume a hint or advance process-local discovery without attempting a SQL write.
Hints remain local location assistance; they do not replace source authority or
change signed revision, source recipe, pin or wire locator bytes.

Shared hint reads use SQL-bounded payload allocation (4,112 encoded bytes) and
accept paths of at most 4,096 bytes. Malformed encodings are ignored as before;
oversized records fail closed before payload allocation. Writes use the same
canonical raw-path encoding and size bounds. Legacy stable-source rendering also
uses these helpers and now delays hint publication until its ciphertext reference
has been verified. Previously a source that opened but produced invalid bytes
could update its location hint before rendering failed.

The native/Git paged fixture now moves an area to a raw Unix path, exercises
incremental discovery through an actual read-only database, checks unchanged
saved hints, and verifies ordinary serving's authenticated update. A second move
invalidates both the serialized and cached paths and uses a durable raw-path hint
outside the discovery prefix after database reopen. Corrupt bytes cannot create
a new hint. A new legacy fixture covers the same verification-before-write and
read-only behavior, malformed/oversized SQL records and overlong write paths.
All 47 locked workspace/all-targets paged tests pass (five core, seven Git,
18 Node and 17 store), as do all 31 ordinary metadata/restore compatibility tests;
eight provisioned compatibility cases remain ignored. The full all-targets test
build, formatting, diff checks and strict locked workspace/all-targets Clippy
pass. No complete ordinary Node rerun or physical Btrfs/remount, topology,
platform or real 1 TiB release qualification ran for this hint integration.

Valid saved locations survive database reopen, but scan cursors remain
process-local. Restart/eviction-safe progress, operational retry/recovery and
physical relocation/source-loss qualification remain required before production
admission. The 1 TiB target includes retained history and is still unqualified.

### Restart-safe native anchor discovery (2026-10-07)

Ordinary Node stable-source serving, including retained paged native/Git data,
now persists Linux Btrfs/ext4 relocation progress in local control records.
Directory enumeration uses bounded 8 KiB `getdents64` buffers and saves the last
consumed directory cookie, rather than the end of a partially consumed buffer.
Resume reopens pinned directories beneath their parents, rejects mount/symlink
crossings, and verifies stable filesystem/inode identity and directory modification,
change and size metadata before seeking. Changed directories restart discovery;
unrelated mount-table changes do not discard completed work. Newly visible roots
are queued before declaring absence. Locator and signed source encodings remain
unchanged. These checks are local location assistance, not data authority or an
atomic snapshot of an actively changing namespace.

Cursors are bounded at 576 KiB, with at most 32 durable jobs, 256 roots, depth 64
and 64 simultaneously open scan frames across the process. Attempt UUIDs and
monotonic generations participate in exact-record CAS publication. Filesystem
work runs outside the SQLite writer; stale publishers return pending rather than
overwriting newer progress. Oversized, corrupt, unknown-version and overflowing
journals fail closed without replacing their records. A terminal found location
can survive a crash before source authentication. Only a verified sector read
publishes its durable location hint and retires the cursor, together in a checked
transaction. Ignored writes or cleanup roll back both changes. Missing areas
retire their jobs without publishing a hint. Explicit/read-only rendering stays
nonmutating. Unsupported filesystems retain process-local discovery.

Validation on Rust 1.99 and Linux 7.2.5-1.qubes.fc41.x86_64:

- The final store library suite passes 136 tests, with 23 provisioned tests
  ignored. Fresh-process fixtures prove saved-cookie progress, attempt identity
  and increasing generations across independent executables. Fault fixtures cover
  stale CAS, the job quota, ignored SQL writes, malformed journals and absence.
- Node passes all 18 paged tests and 32 ordinary metadata/restore compatibility
  tests (eight provisioned cases ignored). A moved legacy source with incorrect
  bytes retains its discovery job without publishing a hint; correcting the bytes
  after database reopen authenticates the source and completes the job. Git
  passes all 90 ordinary tests, with 62 provisioned cases ignored.
- On a disposable 512 MiB Btrfs loop image, targeted tests pass for fresh-process
  progress, nested-subvolume and bind-mount exclusion, and source loss followed by
  missing-job retirement. The existing moved-anchor remount fixture passes both
  phases. A new cursor fixture also passes both phases around an actual external
  unmount/remount: the reopened checkpoint is byte-identical before continued
  progress reaches the target. The owned mount was verified absent, loop device
  detached and image/fixtures removed afterward.
- The locked workspace/all-targets test build passes. The subsequent final
  store-only test additions compile and pass, and strict locked workspace/
  all-targets Clippy, formatting and diff checks pass on the final sources.

The 25 ms scan deadline remains cooperative: individual kernel I/O, reopening
bounded frames and SQL commits can take longer. Direct native Git catalog,
capture/replay and retirement consumers still need durable-discovery integration.
Operational retry/backoff and abandoned-job quota cleanup, continuously changing
namespaces, other filesystems/platforms, complete consumer lifecycle tests and
real 1 TiB dataset/history qualification remain open. This evidence does not
complete R3 or the production release gates.

### Durable discovery in native Git catalog reads (2026-10-07)

Git object-to-anchor lookup now advances the same bounded, restart-safe Linux
discovery journal as Node serving. It consumes bounded raw-path location hints
and verifies native ownership, the manifest content root and the expected Git
object ID before publishing a hint and retiring discovery. Wrong Git mappings
preserve their original records and leave assistance unpublished. Pending or
resource-limited discovery remains retryable when no verified physical copy is
available; a different verified copy can still satisfy the lookup. Corrupt local
catalog assistance fails closed. Manifest serialization and signed bytes do not
change.

Native manifests now accept a local area hint for ownership and verified opens.
Catalog-backed libgit2 construction saves each verified location beside its
manifest; callbacks revalidate ownership and bytes using that hint without
retaining a SQL connection. Both commit constructors use this backend. Diffs,
existing merge-blob verification and stock Git object exports use catalog-assisted
opens as well. Read-only native-ownership preflight can consume saved hints
without migrating the catalog. Read-only and query-only connections never
publish hints or retire discovery jobs. An authenticated writable lookup retires
a leftover job even when its location hint is already current.

The new fixture drives wide-directory discovery through independent Git test
executables, first using a wrong Git mapping and then correcting the mapping.
It checks unpublished hints, preserved manifest bytes, job completion, movement
to a raw Unix path outside the discovery prefix, query-only and read-only job
preservation, and writable cleanup. Libgit2 existence, header, whole-object and
streaming callbacks still read the exact bytes after the catalog connection has
closed. The same fixture passes on both the ext4 host and a disposable 512 MiB
Btrfs loop filesystem. The owned mount was verified absent, its loop detached,
and its image and fixtures removed after testing.

The locked workspace/all-targets test build passes; the subsequent expanded Git
fixture compiles in the package test build and strict locked workspace/all-targets
Clippy. All 18 Node paged tests and 32 ordinary metadata/restore compatibility
tests pass (eight provisioned compatibility tests ignored). This is consumer
integration evidence, not full relocation or production capacity qualification.
The full Git library suite passes 91 tests (63 provisioned tests ignored), and
the full store library suite passes 136 tests (23 provisioned tests ignored).
Formatting and diff checks also pass. No full Node, topology, other-platform or
real 1 TiB qualification ran for this integration.
Remaining Git capture/import/checkout/replay and source retirement, operational
retry/backoff and abandoned-job cleanup, complete physical consumer lifecycle,
other platforms/filesystems and the real 1 TiB dataset/history gate remain open.

### Durable relocation during capture and cleanup (2026-10-07)

Control-aware native root, file and blob-import operations now resolve local
locations through bounded durable discovery. The resolved hint is passed
separately into capture, reconciliation and discard; persisted plans and
manifests retain their original area locator bytes. Reopening a published file
or imported-blob manifest uses the currently pinned area location for content
verification. Standalone APIs keep their existing process-local behavior.

A shared control-store helper reads bounded raw-path assistance, respects both
read-only open mode and query-only policy, and performs filesystem work outside
the SQL writer. Successful native operations publish their location assistance
and retire any discovery cursor together. Operation failure leaves assistance
unfinished; publication failure leaves the caller's capture/cleanup intent
available for idempotent replay. The operation still validates its own native
ownership, source versions, manifest/content commitments and deletion scope.
The location hint neither authorizes source bytes nor replaces the caller's
capture, Git object or retirement authority.

Git staging now hashes captured bytes through catalog-assisted opens, including
after a moved-area capture succeeds. Fetch and generated-merge replay use the
control-aware blob-import capture, reconcile and discard APIs. Backup import
keeps verified locations while joining blob IDs against the descriptor.
Checkout publication accepts a separate hint while preserving native ownership,
content verification and creation of a distinct editable COW inode. Git prune
and Node revision-anchor retirement resolve durable assistance before native,
idempotent deletion; their existing pin/ownership checks remain in place.

Two new provisioned Btrfs fixtures pass. One advances a wide-directory scan
through independent executables, captures root, historical file, raw file and
imported-blob plans, and reopens/reconciles them. After a second move beyond the
scan prefix, separate processes replay every capture and cleanup through a saved
hint, repeat discard, preserve the serialized input plans and leave the source
bytes intact. The other reopens a pending Git stage after area relocation,
verifies the original intent bytes and resulting Git ID, and publishes/edits a
checkout without changing the anchor or source bytes. Four existing Btrfs cases
also pass: checkout conflict safety, fetch replay after external source loss,
interrupted dirty checkout and pruning with physical pins. These ran on an owned
512 MiB loop filesystem, whose mount absence, loop detachment and image/fixture
removal were verified afterward.

The locked workspace/all-targets test build passes, as do the full ordinary Git
suite (91 tests, 64 provisioned tests ignored), full ordinary store suite
(136 tests, 24 provisioned tests ignored), 18 Node paged tests and 32 ordinary
metadata/restore compatibility tests (eight provisioned cases ignored). Final
Clippy cleanup removes an equivalent borrow and simplifies the native fixture's
loop counter; package test builds and targeted anchor, stage, fetch and backup
import tests cover those final sources. Formatting, diff checks and strict locked
workspace/all-targets Clippy pass. No full Node, topology, other-platform or real
1 TiB qualification ran for this integration.

Remaining standalone capture/recovery and best-effort cleanup callers, complete
consumer lifecycle qualification, retry/backoff and abandoned-job cleanup,
other filesystems/platforms and real 1 TiB dataset/history qualification remain
open. These changes do not close R3 or the broader production release gates.


### Operator recovery for unfinished discovery (2026-10-07)

Linux local control and `mutualbackup source-scan` now expose discovery status
and explicit reset. The default catalog is the node control store; an optional
registered repository UUID selects its private Git catalog. Listing uses an
indexed UUID continuation cursor, returns at most 32 summaries and reads at
most one bounded journal payload at a time. Oversized or undecodable journals
still report their area and stored length. Attempt/generation fields describe a
canonical version-1 journal envelope, not cursor usability, source availability
or backup authority. Concurrent changes can alter the next page; this is an
operational view, not a frozen backup snapshot.

Reset abandons the current journal, including malformed or oversized progress,
and frees its active-job quota slot. It does not delete source anchors, physical
pins, saved location hints or Git operation intents. The request applies to
current assistance when executed, even if the caller listed an older attempt.
A blocked operation must be retried to begin fresh work; reset itself neither
scans nor replays that operation. The 32-job admission limit remains in place,
and no pending job is silently evicted.

Every advancing writer reads a per-area durable random epoch before filesystem
work, then compares it together with exact journal bytes inside the short SQL
publication transaction. Reset rotates the epoch and deletes the journal
atomically. Successful hint completion and exhausted scans rotate it as well.
Thus a publisher that observed absence cannot revive a job after another
process created and reset it, even though the journal is absent again. Ignored
fence, hint or cleanup writes roll the transaction back. The epoch is a bounded
16-byte record retained per encountered area, outside the active-job quota;
keeping it prevents arbitrarily late publishers from matching an old absence.
It is local assistance, not a recovery generation or signed authority floor.
Malformed epochs fail closed until explicit reset repairs that assistance.

Git maintenance carries the same validated, pinned source directory into the
catalog operation; renaming/replacing its pathname cannot redirect that operation.
It pins the private catalog directory and validates its marker, registration and
native ownership classification. It opens existing state without normal
repository replay, so blocked checkout intents can remain
pending while scan progress is reset. Node-side maintenance validates existing
stable root identity and backend binding without probing or rewriting it after
a remount. Read-only listing leaves catalog bytes and backend bindings intact.
Withdrawn guarded state and changed root identities are rejected before reset.

The locked workspace/all-targets test build and strict Clippy pass, along with
formatting and diff checks. The full ordinary store suite passes 139 tests
(24 provisioned cases ignored) and the full ordinary Git suite passes 92 tests
(64 provisioned cases ignored). Twelve local control/schema tests, six CLI tests
and the Node catalog-selection/remount-binding fixture pass. A real CLI/daemon
process fixture lists a malformed job, rejects an unregistered Git selection,
resets the job and verifies its absence after daemon restart. Store regressions
cover bounded paginated read-only status, oversized journals, quota release,
absent/present/absent stale-publisher races across independent connections and
reopen, preserved pins/hints, malformed fences and rollback of ignored writes.

Three provisioned Btrfs regressions pass: cursor replay through independent
processes, source-loss retirement of a missing job and Git stage replay using a
saved area hint. The owned 512 MiB mount, loop device, image and fixture were
removed, with mount absence and loop detachment verified. Final review then
keeps the validated source-root pin across maintenance; targeted Git and Node
maintenance, local control/schema and real CLI/daemon restart tests pass on that
refinement, including rename/replacement of the registered pathname. The final
locked all-targets build, formatting/diff checks and strict Clippy also pass.
No full Node, topology, other-platform or real 1 TiB qualification ran.
Operational retry/backoff, remaining standalone
consumers, complete physical/filesystem lifecycle and platform qualification,
and the real 1 TiB dataset/history gate remain open. This increment does not
close R3 or the broader M6 production gates.

### Bounded compatibility records and streamed packed-cache writes (2026-10-07)

Existing coding records now bound collections to the supported 64-shard profile.
When the decoder supplies a count hint, oversized declarations are rejected
before allocating or reading their elements. This covers plan
information/parity roles, root vectors, group roles, transcript storage receipts
and sampled openings. Failure domains are bounded to 256 UTF-8 bytes. Sampled
openings admit at most one 16-byte leaf. General range proofs retain the full
4 MiB geometry (262,144 leaves) and at most 18 sibling hashes; packed-sector
slots and payloads retain the existing 4 MiB sector/16-byte minimum-slot bounds.
The collection visitor caps initial capacity independently of the supplied size
hint and rejects an extra element in unknown-length sequences before decoding
its nested payload. Postcard withholds a count hint when a truncated input has
fewer remaining bytes than declared elements; decoding still has bounded initial
capacity and a bounded element count. These bounds preserve existing valid
shapes, wire versions and signed identities.

Full-information witnesses apply the existing 512 KiB plan budget across the
entire nested collection, reducing the remaining budget before each following
payload is decoded/copied. Both historical byte arrays and compact byte strings
remain supported in Postcard and self-describing CBOR maps. Map decoding no
longer constructs an intermediate untagged representation for each witness.
Version-one maps still accept the absent optional witness field. Semantic plan,
proof, authority and signature verification remain the consumers' responsibility.

The local packed-sector cache now borrows each sector while encoding and emits
one owned record at a time into a single SQL transaction. It no longer clones
all payloads and descriptors or constructs a second batch-sized encoding vector.
All supplied changed sectors are authenticated before the writer is acquired.
A producer error or ignored SQL write rolls back the preceding cache writes;
the ordinary batch helper uses the same affected-row checks. The iterator may
only perform bounded local encoding while holding the writer, without external
I/O or re-entering that connection. Atomicity and existing cache record bytes
are preserved across restart.

Packed-cache encoders and SQL reads use a conservative 64 MiB per-record cap.
The largest existing shape is a 4 MiB payload plus 262,144 fixed-field slots;
its Postcard record fits this cap including worst-case varints and the enclosing
record. This local cache bound does not raise any private metadata, frame,
checkpoint or dataset admission limit.

Validation: all 114 core, 140 ordinary store and 92 ordinary Git tests pass
(24 store and 64 Git provisioned cases remain ignored). The eight transport
codec tests, two existing packed-cache cases, the new cache atomicity/reopen
fixture and the retry-input pin/cleanup fixture pass. Coverage includes
oversized declarations and unknown-length collections, exact/over-budget
witnesses in both versions, preserved signed bytes and transcript replay,
late producer/SQL-ignore rollback, authentication before cache writes and exact
historical cache bytes after reopen. The final locked workspace/all-targets
build, formatting/diff checks and strict Clippy pass.

The provisioned five-peer native Git packed-checkpoint fixture passes on
disposable Btrfs in 574.39 seconds. It verifies exact Git history and bytes,
checkpoint grace retention, obsolete group retirement, expired packed-cache
and READY-shard deletion, physical history reclamation and two seed-only
recoveries after complete owner loss. The second recovery follows that cleanup
and erases the ordinary Git export too. Recorded source and test-binary hashes
match after execution. The owned 2 GiB image, mount, loop device and fixture
were removed, with mount absence and loop detachment independently verified.
This is a single in-process five-peer fixture; no full Node suite,
five-daemon topology, other-platform or real 1 TiB qualification ran here.

The packing result, flat catalog and checkpoint still materialize complete
collections. Their paged replacements, quota reservations, generation floors,
normal capture/restore/retention and seed-only migration, enclosing R2 admission
and real 1 TiB dataset/history qualification remain open. Streaming the extra
cache encoding alone does not demonstrate bounded whole-backup memory or close
R2/R3.

### Retained legacy revision migration (2026-10-07)

An explicit Node operation now connects whole legacy private conversion to
retained paged publication. It loads the original signed revision with the
existing SQL byte bound, requires the local secret to match the owner writer
fence in the current checkpoint, and preserves the original revision and flat
head. The new signed body uses a separate caller-supplied operation ID, names
the old signed body hash as its parent and advances its sequence by one.

An immutable bounded migration journal binds the operation ID, old body hash,
dataset scope and new writer. Deterministic per-role intent IDs retain staged
pages across interruption. Conversion authenticates the complete supported
legacy private schema, data and Git blob bytes before staging private pages.
The operation adds their encrypted source references, the encrypted bootstrap
and original data references to a per-operation SQL ordering queue. Indexed
cursor reads bound both keys and payloads before allocation; the source builder
holds one record at a time. Retrying reconstructs this disposable queue from
authenticated inputs rather than trusting a stale tail. No converted-page map
or complete source vector is assembled.

Every original data sector requires an exact local stable native/Git recipe.
The operation checks signed legacy membership, source offset and both ciphertext
commitments before signing; root publication rechecks sources and retains
physical anchor counts in its existing atomic writer transaction. Old data
addresses remain unchanged. Missing stable sources, path-only and Inline data
recipes fail explicitly. A completed retry reopens the verified retained
publication without rereading original metadata. Original flat records and
recipes remain available for the existing consumers.

Cancellation first persists its operation fence, then uses typed atomic root
cancellation or fences unfinished member intents and validation. Interrupted
cancellation resumes after reopen; its ID cannot publish again. The queue is
discarded and bounded cleanup releases one source binding, page binding, pin
or native-index row per step. Shared retained roots and anchors preserve their
ownership. Fencing tombstones remain until authenticated generation-floor
retirement exists.

This connects the explicit retained migration path; normal capture/restore,
packing, coding/checkpoint, production head/retention and seed-only migration
are still required before paged production activation. It does not qualify the
1 TiB target or add physical quota reservation.

Validation: all 20 paged Node tests, 141 ordinary store tests and 32 ordinary
snapshot tests pass. The store suite retains 24 provisioned cases and the
snapshot suite retains eight; they were not run here. New fixtures qualify
native private versions 1/3 and Git-bearing versions 4/5, exact original data
addresses, shared root/anchor retention, completed retry without old metadata
reads, publication rollback after SQL IGNORE, missing stable recipes, changed
legacy identity/writer rejection and catalog-ID collision rejection before a
journal is claimed. Cancellation is exercised after publication and after
staging private pages without a source publication, including interruption,
reopen, retry fencing and bounded cleanup. A separate Node fixture verifies
certified versus missing/pending local writers with a quorum-signed checkpoint,
original flat record/checkpoint preservation, reopen/retry and
cancellation after loss of the writer secret. The indexed cursor fixture covers
exclusive ordering, deletion/reopen, empty keys and oversized keys/payloads.
The final expanded interruption and Node fixtures pass again on the final
test source. Locked workspace/all-targets build, formatting/diff checks and
strict Clippy pass. No full Node, native-filesystem, topology, other-platform
or real 1 TiB qualification ran in this increment.

### Retained paged native restore (2026-10-07)

Linux can now restore the native tree from an explicitly retained local paged
revision through the Node API. The consumer streams the authenticated namespace
and file recipes, resolves each source against the published native validation
index and verifies both ciphertext commitments before decrypting a sector.
Sparse extents seek directly to their signed offsets. Raw path bytes survive
without UTF-8 conversion. Forward hard-link aliases wait for their primary
inode; repeated file recipes reuse that inode without fetching its bytes twice.
This restores the native portion of Git-bearing revisions without installing
their Git history.

Per-target SQL indexes retain expected paths, inode identities, link groups and
deferred aliases. Cursor reads bound keys and payloads before allocation; the
restore holds one file recipe record and sector at a time. Parent traversal
checks pinned directory identities without retaining a descriptor stack. An
exact namespace check rejects untracked or replaced children before directory
metadata is applied in descendant-before-parent order, with root metadata last.
The temporary hard-link pool is removed before publication. These indexes are
disposable and rebuilt after an interrupted construction.

Publication reuses the existing serialized, inode-bound restore journal,
no-replace rename and parent-directory sync. Version-3 jobs bind the paged
signed-body hash through a domain-separated identity and cannot adopt a legacy
reservation, even with the same UUID. An ignored initial journal insertion now
fails explicitly instead of repeatedly trying to reserve the target. Journal
enumeration bounds individual SQL records. A Publishing job can finish after
retained-root cancellation without fetching retired metadata or data; unfinished
construction still requires live retained authority.

This is an explicit local Linux native-tree consumer. Normal paged capture,
Git-history installation, remote/seed-only paged restore, checkpoint/retention
activation, quota reservation and real 1 TiB dataset/history qualification remain
required before production admission.

Validation: the locked workspace/all-targets build and strict Clippy pass. All
23 ordinary tests selected by `paged_` pass, along with 33 ordinary snapshot
tests and the separate Node certified-writer/reopen fixture. The shared
reservation-isolation test appears in both ordinary selections. Eight
provisioned snapshot cases remain ignored; they were not rerun in this slice.
The new restore fixtures qualify multiple namespace pages with 450 directories,
raw names, sparse extents, forward hard links, exact mode/timestamps, existing
target refusal, corrupt data, ignored index/journal inserts, unexpected children
and interruption after rename followed by cancellation/reopen. The final
strengthened directory-stat assertions and failure/replay fixture pass again.

The new explicitly provisioned Btrfs Node fixture passes capture, working-file
edits, retained conversion, reopen and native restore. It verifies original
CRLF/NUL bytes, hard-link inode equality, nested restrictive directory modes and
exact nanosecond timestamps, plus a 1 TiB logical sparse file with less than
1 MiB allocated after restore. This is sparse-offset correctness, not a real
1 TiB retained-data capacity qualification. The reflink acceptance script now
selects this exact fixture; its shell syntax passes, while the complete script
was not rerun here. Source and test-binary hashes match
after execution. Its owned disposable image, mount, loop and fixtures are
removed with mount absence and loop detachment independently checked. Full
Node/Git suites, daemon topology, release artifacts and other platforms were
not qualified in this increment.

### Streaming paged Git graph admission (2026-10-07)

Retained paged publication now verifies the complete Git ref/commit/tree/tag
graph and blob membership before creating native validation or publishing roots.
Previously the paged readers checked framing, geometry and object hashes, but
could accept a signed ref targeting a tree, missing graph members or unreachable
objects. The enclosing descriptor now also requires its repository identity to
match the protected root during sealing, bundle construction and authenticated
opening. Existing signed formats and original retained revisions remain intact.

The graph consumer streams original object fragments without reassembling a
metadata object. Tree parsing retains one bounded component and its target OID;
libgit2 parses each complete entry through a disposable memory ODB. Commit/tag
parsing retains a 64-byte line prefix, fixed signature/timestamp state and a tag
name hash. Large messages, signatures, optional headers and parent lists need no
whole-object buffer. Original byte lengths and Git OIDs remain verified by the
authenticated object reader. This adds no replacement whole-object ceiling.

An encrypted private temporary SQLCipher index holds nodes, edges, per-tree name
uniqueness and traversal frames. Indexed reads bound keys/payloads before
allocation. Its mutations share one record transaction on that private store,
avoiding a durable commit per scratch row and keeping external I/O outside the
production catalog writer. A rejected validation rolls back the scratch batch.
Depth-first traversal holds one frame at a time, checks target kinds
and cycles, and computes expanded tree path lengths for shared subtrees. It
rejects unsafe root names, conflicting tree entries, unsupported modes,
invalid symlink lengths, incorrect annotated-tag names, missing targets and
unreachable metadata/blobs. The edge budget uses the existing 64-million-record
geometry; Git paths retain the current 4 KiB staging bound. Selected and unborn
heads retain the paged ref codec's explicit semantics.

Blob plaintext OIDs and symlink target contents still require the enclosing data
consumer's verification; this graph pass does not fetch blob payloads. Legacy
conversion already authenticates its original Git blob bytes. Paged Git-history
installation, normal capture/admission, packing/checkpoint/retention and seed-only
consumers, physical quota/scratch lifecycle and real 1 TiB qualification remain
required before production activation.

Validation: the final locked workspace/all-targets build, formatting/diff checks
and strict Clippy pass. All 100 ordinary Git tests pass on the final source:
the 1,200-entry/shared-history fixture ran separately in 1.26 seconds, and the
remaining 99 cases passed together. The first complete run also passed before
the scratch transaction refinement, but its per-row filesystem journal waits
made the scale case unnecessarily slow. The final ordinary store suite passes
142 cases, and all 25 ordinary tests selected by `paged_` in Node pass.

Eight new graph fixtures cover shared DAGs, nested tags, raw names, unborn
heads, missing/wrong/unreachable members, unsafe/conflicting tree entries,
symlink lengths, expanded paths, cycles, unavailable/corrupt pages and ignored
index writes. Generated graphs and individual commit objects above the old
32 MiB flat bound pass without adding a new object-size ceiling. Text admission
is compared directly with libgit2 for selected valid/invalid signatures and tag
headers, signed timestamp boundaries, long leading-zero timestamps and non-UTF-8
authors at chunk sizes 1, 7 and 32 KiB. The many-entry tree crosses fragment
boundaries and shares history subtrees. A store fixture qualifies atomic commit,
rollback after later errors or ignored writes, nested-transaction rejection and
durable reopen. Two Node fixtures prove wrong ref targets fail before pending
native validation and stay rejected after reopen, while a valid graph can still
publish; sealing and authenticated open reject another repository identity.

Recorded source/test-binary hashes match after the final runs. The runs leave
64 provisioned Git cases, 24 store cases and the selected Node native fixture
ignored. No full Node suite, provisioned filesystems, daemon topology, release
artifact, other-platform or real 1 TiB qualification ran in this increment.


## Disposable encrypted record indexes (2026-10-07)

`RecordScratchStore` uses a keyed unnamed attached SQLCipher database. It forces
file-backed temporary storage before attachment and rejects SQLite builds that
force all temporary databases into memory. A 1 MiB page cache, cache spilling,
DELETE rollback journals and a checked page-count ceiling bound the database;
synchronization is disabled for this disposable state. Each current consumer
allows at most 64 GiB of database pages (four times the catalog stream ceiling).
This is a finite implementation limit, not a qualified supported catalog size.
Rollback-journal disk space and concurrent jobs need separate physical admission.

Git graph admission uses this store and a libgit2 repository wrapping a memory
ODB, removing both named scratch databases and parser directories. Native restore
keeps inode/directory/link/alias indexes in the private store and batches their
writes without holding the production catalog writer during page and sector I/O.
The durable restore journal and pinned staging tree still drive crash recovery;
a retry rebuilds the disposable index and removes rows from earlier versions that
stored these indexes in the durable catalog. Publication still requires exact
namespace/inode checks and a final retained-authority check.

The Linux process-lifecycle test writes and replaces 8 MiB of payloads, spilling
both database and rollback-journal pages, inspects their live descriptors for allocated blocks,
zero hard links and absence of plaintext payloads/SQLite headers, then kills the
child and verifies that no named scratch files survive. Separate tests exercise
bounded reads, duplicate/ignored writes and rollback after the page budget is
exhausted. Native retry coverage injects ignored writes in the private index and
simulates old durable index rows across reopen.

The explicitly provisioned Btrfs retained-native capture/migration/reopen/restore
fixture passes (24.71 seconds), preserving sparse extents, raw bytes, hard links
and directory metadata. Its loop device, mount and image were reclaimed. A sparse
1 TiB logical file does not qualify the required 1 TiB retained dataset capacity.
Formatting, strict locked workspace/all-targets Clippy and the locked all-targets
test build pass. The final binaries pass all 144 ordinary store tests (25
ignored), all 100 ordinary Git tests (64 ignored) and 25 paged Node tests (one
ignored native fixture, run separately above). Source and binary hashes remained
unchanged across qualification. The complete Node, topology, platform and release
artifact gates were not rerun for this increment.

Other operating systems/VFS implementations, aggregate scratch reservations,
normal paged capture/Git-history installation/checkpoint/retention/seed-only
consumers and real 1 TiB qualification remain open; R3 and M6 are not complete.


## Physical admission for anonymous Linux indexes (2026-10-07)

Linux disposable record stores now use a dedicated SQLite VFS that accepts only
anonymous temporary database/journal files. Durable catalogs retain their normal
SQLCipher VFS. The adapter pins the chosen directory, delegates SQLite clock and
randomness services to the original VFS, and closes every borrowed file before
unregistering. File reads preserve SQLite's zero-filled short-read contract;
logical EOF remains separate from physically reserved allocation tails.

Every growing file reserves real extents with `fallocate(FALLOC_FL_KEEP_SIZE)`
in 64 KiB increments before writing. Database and journal files share one physical
job budget; the default is three times the database ceiling plus three allocation
tails. The 64 GiB database ceiling therefore has a 192 GiB + 192 KiB physical
ceiling, not a reservation of that entire amount at startup. Unsupported physical
allocation fails closed. On anonymous Btrfs files, data CoW is disabled while the
file is empty so rewrites stay inside reserved extents; SQLCipher authenticates
the encrypted pages. The attached database is opened with file storage before
restoring memory storage for SQLite's other temporary structures. Ordinary record
queries use their primary index and do not materialize a sorting workspace.

A private, owner-checked directory at
`/tmp/.mutualbackup-scratch-allocation-<uid>` supplies the shared advisory lock for
this host user. This small rendezvous remains across jobs; its inode is checked
after acquisition and its timestamp refreshed. Actual index files remain unnamed
and are reclaimed on normal exit or process death. Cooperating processes sharing
this rendezvous serialize free-space checks and extent reservation, including
workspaces in different Btrfs subvolumes. This does not control external writers,
different users or isolated `/tmp` namespaces.

Node Git admission and native restore place their indexes beside `control.db`,
with at least 32 MiB of remaining headroom plus all configured parity headrooms
in the same allocation pool and 64 KiB per volume. Runtime pool identity uses
the Btrfs filesystem UUID across subvolumes/bind mounts and the current device
ID on ordinary filesystems; it is not a durable source identity. Current control
and parity WAL checkpoint-copy space is re-read before each allocation through
pinned parent descriptors. Registry input is bounded to 4 MiB and at most 1,023
volume records for this admission path; the durable registry format is unchanged.

An actual temporary-file write failure can poison SQLite's private pager. Such
an index is discarded rather than reused. The enclosing graph validation or
native Building job fails before publication; retry creates a fresh index, while
the durable restore journal still owns staged filesystem cleanup. Non-I/O batch
errors continue to roll back normally. This admission does not reserve a whole
future job, replace retained dataset/history quotas, or coordinate every source,
restore and parity writer. Those consumer/scheduling/platform gates and real
1 TiB qualification remain open; R3 and M6 are incomplete.

Final qualification uses unchanged source and test binaries: all 148 ordinary
store tests (26 ignored), 100 ordinary Git tests (64 ignored), 25 paged Node tests
(one ignored) and 56 ordinary volume tests (one ignored) pass. The expanded
2,000-directory native restore fixture configures parity headroom above free
space, rejects actual index spill before publication, retains its Building job,
reopens, lowers headroom and rebuilds the exact sparse/raw-name/hard-link tree.
Other cases verify physical quota/headroom failure and fresh-index retry,
checkpoint growth under renamed pinned parents, zero-filled short reads, EOF and
truncate accounting, encrypted file/journal spill, SIGKILL reclamation and actual
cross-process blocking/resumption at the admission lock.

The provisioned Btrfs index rewrite/rollback/commit/quota-cleanup fixture passes
in 1.20 seconds; native capture/migration/reopen/restore passes in 27.82 seconds.
Their mount, loop device and image were reclaimed. Formatting, strict locked
workspace/all-targets Clippy, the locked all-targets test build and acceptance
script syntax pass. The complete acceptance script, topology, remaining platform,
release-artifact and real retained 1 TiB gates were not rerun or closed.

### Retained migration and ordinary flat recovery coexistence (2026-10-07)

Retaining a paged successor preserves its original flat revision and sector IDs.
Historical data bindings now keep ordinary flat repair usable after native anchor
loss: a downloaded flat recipe must match the live retained owner's complete
sector reference, guild, signed ciphertext root and Merkle commitment. The
fallback is limited to authenticated historical data bindings. Private pages,
bootstrap sectors and scoped paged-only data retain their existing strict repair
and replacement rules. Arbitrary Inline rows cannot override retained authority.

Ordinary snapshot restore and resumed publication re-anchor unavailable retained
historical sources before reporting completion. Healthy native sources do not
require recapture. Recovery enumerates data owners through the existing partial
sector index, reading one checked owner/tombstone at a time. Every live owner is
rebound through the exact catalog/source/generation fence, authenticating the
replacement native range and transferring both anchor counts atomically. Valid
cancelled owners keep their pins until their own cleanup runs. Repeated sector
references do not create duplicate source bindings.

The durable recovery intent owns a completed capture before any retained source
moves. Interruption can therefore leave different owners on different verified
anchors without losing either capture. If the restored tree disappears, recovery
reads the completed manifest without replaying capture or accessing the lost
source, then atomically moves ownership into the existing anchor-retirement
journal while retiring the exact intent. A fresh restore can build a new capture;
retirement waits for all retained and flat recipe pins to move. Capture discard
also rejects pinned output. Final flat recipe/manifest publication rejects SQL
IGNORE and keeps its intent on any incomplete write.

This corrects coexistence with original flat backup/recovery. It does not
activate paged capture, packing, checkpoint/retention or seed-only paged recovery,
and does not qualify the retained 1 TiB production target or other platforms.

Qualification: four supported historical private layouts (1/3/4/5)
pass authenticated flat data repair after anchor loss and reopen, including corrupt
bytes, wrong guild and altered fallback rejection. The indexed owner cursor
passes cancelled-owner, reopen and malformed-key cases; flat finalization passes
stale intent and ignored insert/delete rollback. Disposable Btrfs passes native
capture, two retained owners, a 1 TiB sparse file, source/anchor loss, ordinary
restore, interruption after one transfer, loss of that restored tree, durable
capture retirement and another restore after reopen. Exact bytes, hard links,
source generations, stale replacement rejection, shared pins, retirement cleanup
and original flat revision preservation are checked. This native gate passes in
32.10 seconds on `270c040`. The locked ordinary workspace on that source passes
900 tests, zero failed, 116 ignored, including 418 ordinary Node and 151 ordinary
store tests. Ignored provisioned cases remain separate qualification obligations.

The expanded complete five-peer native Git gate also passes on `270c040` in
680.38 seconds. Test-only successor `b6e52bc` reloads the owner's control and
volume state through normal startup after deleting its source and external
anchors, retaining the existing exclusive data-directory claim. Local packed
caches, recovery downloads and READY payloads are erased too, forcing ordinary
flat peer reconstruction. That complete gate passes in 527.82 seconds: both
retained owners move to generation-one native bindings with shared pins; exact
working bytes, historical objects and refs survive; the signed checkpoint stays
unchanged. The existing two subsequent complete owner losses, seed-only recovery,
stock Git interoperability, grace-window protection, history-anchor reclamation,
and expired packed-cache/READY-shard deletion continue to pass.

Tracked source and test-binary hashes match before and after both peer runs.
Disposable mounts, images and loops were reclaimed; independent checks find no
remaining fixture mount, loop device or network namespace. Formatting, strict
locked workspace/all-targets Clippy and the locked all-targets test build pass on
the restart successor. These are Linux library gates, separate from the required
five-daemon topology, exact release artifact, other platform and real retained
1 TiB qualifications. R3 and M6 remain open.

### Bounded packed-sector descriptor streams (2026-10-07)

`CatalogPackedSectorRoot` authenticates a guild-scoped Packing record stream,
packing version, profile and exact sector/slot/source-occurrence/byte summaries.
The version-one grammar is one header followed by exactly the profile's number
of slot fragments for each contiguous sector index. Each fragment contains at
most 128 original `PackedSlot` values, bounded to 24,832 encoded bytes. Nested
length declarations are checked during decode. The typed root has a 512-byte
decode cap. Builders retain one partial catalog leaf and the tree frontier;
semantic validation retains one active sector hash and fixed counters. Neither
reader nor builder assembles a complete sector descriptor vector. A 4,096-slot
descriptor larger than a catalog leaf is covered explicitly.

The sector hash streams exactly the original Postcard tuple, including its
vector-length prefix and original slot encodings. Existing flat catalog hashing
also feeds Postcard directly into BLAKE3 instead of allocating a second complete
encoding. Hash domains, signed layouts and IDs remain unchanged. Independent
reference encodings verify all five historical catalog versions. The validated
legacy adapter borrows descriptor vectors in bounded fragments; it converts only
descriptors and does not rewrite or replace signed proofs/bindings/attestations.

Readers enforce header and fragment versions, contiguous indices/offsets, exact
fragment sizes, profile geometry, source offsets/lengths and nonzero identifiers,
version-specific flat/Merkle roots, original sector IDs and the final nonempty
sector rule. Exact summary checks occur before yielding the final record; full
authenticated EOF remains required. Encoding, semantic, storage and fetch errors
permanently fence their builder/reader. Root summaries count source occurrences;
this stream alone cannot reject duplicate source chunks across sectors or prove
complete source coverage, zero-subtree semantics, owner/member authority or the
packed Merkle commitment's correspondence to authenticated source proofs. Those
disk-backed joins and the enclosing packing/checkpoint root remain mandatory
before protection can be claimed.

A SQLCipher store fixture stages the multi-page descriptor child-first, rejects
publication at incomplete boundaries, reopens and resumes idempotently, publishes
the typed root through immutable bundle bindings and reads its complete stream.
Two intents share the same closure; cancelling one preserves the other, while
cancelling both permits bounded pin release and complete page reclamation.
Retired intent IDs remain fenced. This exercises existing durable catalog
ownership and does not activate a new Node/checkpoint format.

Qualification: all 123 core and 153 ordinary store tests pass, with 26 provisioned
store tests ignored. Cases include malformed nested lengths, noncanonical and
truncated encodings, incorrect IDs/summaries/geometry, partial sectors, empty and
interior-hole sectors, callback failures and failure fencing. Formatting and
strict locked workspace/all-targets Clippy pass. The concurrent store run exposed
a preexisting discovery fixture that deliberately exhausted the process frame
pool; only saturating fixtures now use an isolated pool. Production scans and
resumed scans still share 64 frames, and a regression verifies cap enforcement
and capacity release across scan lifetimes.

The complete locked workspace on `5579541` passes 911 tests, zero failed, 116
ignored, including 418 ordinary Node tests. The locked all-targets test build
passes. Disposable Btrfs retained native migration/source-loss/recovery passes
in 28.07 seconds. All 233 tracked-file hashes and both store/Node test-binary
hashes match before and after that native run. The mount, image and loop device
were reclaimed; independent mount/loop/network-namespace checks pass. This is a
Linux library recovery gate, separate from full peer topology, installed release,
other-platform and real retained 1 TiB qualification.

Source authentication, unique/complete source joins, coding records, enclosing
packing/checkpoint publication, retained-history quota reservations, incremental
edits and normal capture/recovery consumer activation remain open. This codec
does not qualify real 1 TiB retained dataset capacity or close R3/M6.

### Ordered complete-source packing proofs (2026-10-07)

`CatalogPackedSourceRoot` supplies the second guild-scoped Packing stream. Each
source header binds owner, protected root, object ID and one complete ciphertext
Merkle commitment. Headers occur in strictly increasing source-ID order, so
duplicate sources reject with fixed state. Exactly the profile's number of
chunk proofs follow in fragments of at most 64 entries. Each entry contains its
subtree root and at most 18 siblings; chunk/start-leaf/leaf-count fields derive
from the fragment position and validated profile. Every reconstructed version-one
opening must verify against that source's commitment. Thus complete proof
coverage and one consistent commitment are checked without a catalog-sized map
or repeated per-chunk source identities/commitments.

Nested proof and sibling lengths are bounded during decode. Records have a
39,232-byte cap within the existing generic record limit; fixed roots have a
512-byte decode cap. Roots bind the profile, exact record/source/chunk counts and
complete ciphertext byte total. Those byte counts are distinct from retained
plaintext size or quota accounting. Readers verify totals and complete active
sources before yielding the declared final record; authenticated EOF remains
mandatory. All semantic, encode, storage and fetch errors fence further use.

Qualification: all 129 core tests and strict locked workspace/all-targets Clippy
pass, with formatting and diff checks. Tests cover 512 ordered sources across
many pages, one source whose proofs cross page boundaries, incomplete fragments,
duplicate/out-of-order identities, wrong offsets and reordered/corrupt openings,
substituted summaries, unfulfilled record counts, oversized nested declarations,
truncation/noncanonical bytes and callback/page corruption. Minimum one-leaf
sources and the maximum 4-MiB/16-byte profile's 18-sibling paths are exercised;
incomplete maximum-profile sources cannot finish. This increment changes no
existing signed catalog or active consumer. The preceding 911-test workspace
and native recovery gate qualified `5579541`, before this new codec was added.

The next consumer must join every descriptor slot to exactly one source proof,
reject incomplete/duplicate descriptor coverage, check virtual-zero and packed
Merkle composition and bind each source commitment to verified revision/member
authority. Enclosing packing/coding metadata capacity must account for all
streams at the declared retained 1 TiB geometry; per-stream limits alone do not
qualify the aggregate. Bounded scratch/index ownership, quota reservations,
signed checkpoint publication and normal capture/retention/recovery activation
remain required. R3 and M6 remain open.

### Compact packing references and complete subtree streams (2026-10-07)

Full source identities repeated in every descriptor slot, combined with repeated
source-proof sibling paths, would exceed the existing metadata budget at the
required dense 1 TiB geometry. Root format two addresses that representation
cost while keeping format-one readers and all existing signed bytes intact.
The record enums append compact variants; no existing discriminant changes.

Compact slots carry a 32-byte source key, chunk index and content hash. The
key domain-binds the complete owner/root/object identity and remains stable
when another source is inserted or removed. It is not a dense ordinal. Source
offset and full slot length derive from the validated profile. The descriptor
reader resolves each key against its authenticated source index, verifies the
key/identity binding, reconstructs bounded original slot fragments and hashes
their exact original encoding. Historical sector IDs, version-specific roots
and input geometry remain unchanged. Missing, substituted and failed resolution
fence the reader. The full-record-only entry point rejects compact roots.

Complete-source format-two records carry every chunk subtree root in order,
up to 64 per fragment. Exact coverage and recomposition authenticate the source
commitment without repeating sibling paths. A valid prefix remains staging
data; source completion and full authenticated EOF are mandatory. Builders may
accept original proofs, validate their openings and compact their roots, or
accept direct subtree fragments. Readers reject mixed format-one/two bodies.

`MerkleSubtreeAccumulator` composes both source and packed-sector commitments
with at most 19 hashes. The original `merkle_commit_subtrees` helper now uses
this frontier instead of copying all roots and intermediate levels. A separate
virtual-zero subtree helper computes the unbound root without allocating a
payload; complete commitments retain their original length binding. Invalid
pushes fence reuse, and incomplete or excessive coverage cannot finish.

Qualification: all 134 core tests and strict locked workspace/all-targets Clippy
pass, with formatting/diff checks. Tests independently compare payload Merkle
commitments, original descriptor records/IDs and stable-key hashes; exercise
maximum frontier width, ordering, zero roots, incomplete coverage, source-path
corruption, mixed formats, missing/substituted resolution, nested length bounds
and failure fencing. A conservative size fixture accounts for worst-case
descriptor indices, all source records, framing and full 64-KiB page ceilings
at every index level for dense 1 TiB/64-KiB-source/16-KiB-slot geometry. Both
record/page occurrence limits and the aggregate 16 GiB metadata budget hold.
This is a structural codec calculation, not real 1 TiB data, retained-history,
coding/checkpoint capacity or incremental-work qualification. Bounded store
joins, certified authority, quotas and consumer activation remain open.

### Bounded local packing joins and checked bundle roles (2026-10-07)

`CatalogPackingValidation` binds the guild scope, exact descriptor/source roots
and compatible profiles/counts. Both streams and the fixed descriptor share the
existing 16 GiB represented-metadata and one-million page-occurrence budget.
The local descriptor decodes within 2 KiB. This is a local validation manifest,
separate from a signed checkpoint and the complete packing/coding capacity policy.

`CatalogPackingIndex::build` takes ownership of a caller-placed/admitted
`RecordScratchStore`, a bounded page fetcher and a required source-authority
callback. The caller must authenticate the roots and bind each source identity
and exact commitment to certified revision/member/writer authority. The source
stream is verified through full EOF before descriptor traversal. Its stable
source keys and chunk subtree roots populate primary indexes. Compact descriptor
resolution reads one bounded source row. Each original slot consumes exactly one
unused source chunk, records its sector/slot/content-hash placement and adds its
subtree to the fixed Merkle frontier. Virtual-zero mappings require the canonical
zero subtree and flat content hash; empty slots contribute the same zero root.
Every completed sector must reproduce its declared commitment, and its original
ID is independently checked by the descriptor reader.

Completion requires descriptor EOF, no partial sector and no unused source
chunk. Insertion, placement CAS and the final marker check affected writes and
exact bounded readback. The private scratch transaction rolls back every prefix
on semantic, authority, fetch, physical/quota or SQL failure. A failed owned job
drops its anonymous database/journals; retry builds a fresh index. Memory retains
bounded fragments, one active sector/frontier and checked SQL rows with a 1 MiB
page cache. It holds no production catalog writer during external page work.
The caller can use existing workspace/checkpoint-reservation/headroom admission.

Only a completed index can construct its checked local bundle. Descriptor and
source roles bind to exactly their typed roots and two durable intents. Ordinary
atomic publication rechecks intent ownership; incomplete trees, immutable
descriptor changes and cancelled intents cannot publish. The disposable index
does not survive reopen: a consumer must rebuild validation before relying on
the reopened bundle. This adds no signed authority, data-payload verification,
retained-history quota or remote protection claim and activates no Node consumer.

Qualification: all 134 core and 158 ordinary store tests pass (26 provisioned
store tests ignored), with formatting/diff checks and strict locked
workspace/all-targets Clippy. Tests cover both full and compact codecs, 2,048
sources/8,192 exact placements across multiple pages, real database spill beyond
the fixed cache, canonical manifest decode and aggregate root/page-budget bounds.
Adversarial cases recompute individually valid descriptor IDs while substituting
duplicate/missing sources, virtual zeros, content hashes or packed commitments;
the cross-stream join rejects them. Source authority denial, late cancellation,
corrupt source/descriptor tails and ignored chunk insert/update/completion writes
cannot leave completed state. Database quota exhaustion fails closed and a fresh
larger index succeeds. Durable two-role staging rejects partial publication,
reopens/rebuilds, publishes immutable bindings, reopens again and cancels/reclaims
both closures. Orphan scratch prefixes cannot be adopted as validation evidence.

Certified paged checkpoint/source authority integration, coding records, the
complete enclosing capacity/quota contract, incremental edits, normal
capture/checkpoint/retention/seed-only activation, filesystem/platform and real
retained 1 TiB qualification remain open. R3 and M6 are not complete.

Exact-source follow-up on `5841bd2`: the locked workspace run stopped in Node
with 417 passed, one failed and 21 ignored. The mixed packed-group replacement
fixture failed its initial coordinator reachability check. Earlier package
suites, including all 134 core tests, passed. An isolated package-target retry
on the unchanged source passed in 193.62 seconds; that retry uses a different
feature-unified test binary and does not turn the failed workspace gate into a
pass. Its synchronous large packing/proof work shares the default Tokio thread
with all five peer loops, a scheduling concern to correct and requalify.

The separate locked store run passes 158 tests with 26 ignored, and the locked
workspace/all-targets test build passes. The provisioned Btrfs retained native
migration/recovery fixture passes in 33.95 seconds. All 235 tracked-file hashes
and both workspace test-binary hashes match before/after native recovery.
Disposable mount/image/loop cleanup and independent mount/loop/namespace checks
pass. The full workspace gate and original R5 topology/signature issue remain
open; these results do not qualify release artifacts or real retained 1 TiB data.

The mixed packed-group fixture now uses two Tokio workers so its five peer
loops can progress during synchronous packing and certificate/GC checks. No
production timeout or reachability rule changes. Formatting, compilation and
strict workspace/all-targets Clippy pass; full workspace requalification is
pending. This fixture correction does not diagnose the original R5 stall.

### Trusted legacy packing authority and paged candidates (2026-10-07)

`CatalogPackingAuthority::from_legacy_checkpoint` imports an existing legacy
certificate only after bounding its canonical envelope to the unchanged 32 MiB
legacy cap, matching a caller-supplied trusted checkpoint hash, and verifying
its complete quorum/revision/fence/packing joins. This is a bounded migration
bridge; it does not replace the flat legacy verifier with a scalable consumer.
Membership, latest base fences, retained chain heads, revision IDs and unique
source authority go into the same private encrypted scratch store used by the
subsequent packing join. Source rows use owner/root/object order and have a
bounded exclusive cursor; no dataset-sized map or dense source ordinal is needed.

All retained sources remain required, including those owned by removed members
or signed under historical writer fences. Legacy authenticated catalogs already
bind their source commitments through the verified certificate. Flat-only
history requires an owner-signed binding, matching epoch-quorum attestations,
or a new owner/writer-signed paged source root binding the same flat source.
Migration evidence must match the exact source and signed flat root. Attesters
must be current base members, agree on the commitment and reach the base quorum;
duplicate signers and wrong epochs fail. Legacy certificates without an epoch
accept owner bindings but cannot supply epoch-bound attestation authority.

New paged candidates verify both signatures, base membership and the latest
writer fence in that base, globally unique revision IDs and exact continuation
of each retained chain. Every signed source root must reach authenticated EOF,
including its exact bootstrap-sector join. Identical shared source commitments
deduplicate; conflicting flat roots or commitments fail. Mutation methods
consume the owned job, so cancellation, corrupt tails, ignored writes and quota
failure cannot leave an adoptable authority prefix. Retry rebuilds a fresh job.

The final join requires exactly the unique source cardinality in the authority
pool. Together with ordered unique source records and exact commitment lookup,
this rejects omitted retained sources and same-count substitutions. Both source
and descriptor EOFs and complete chunk placement remain mandatory. The checked
result retains its trusted base and exposes bounded signed-candidate and
placement cursors. The legacy envelope, new signed roots/source pages, migration
evidence and both packing streams share the existing aggregate byte budget;
new page closures also share the page-occurrence budget. Physical scratch
placement, checkpoint reservations and headroom remain caller admission duties.

Qualification: the full locked store suite passes 165 ordinary tests with 26
ignored before the final spill fixture was added. All eight final focused
authority tests pass, including 16,002 sources, real spill beyond the fixed
1 MiB cache, ordered traversal and a fresh rebuild after the final source-page
fetch fails. Tests also cover trusted-hash/quorum/signature rejection, stale
writers, removed owners, retained tombstones, two chained paged candidates,
all existing authenticated packing-certificate evidence paths, incomplete
bootstrap joins, wrong source cardinality/substitution, duplicate attesters,
wrong epochs/roots, orphan rows, ignored candidate insertion and aggregate
byte/page budgets. Formatting/diff checks and strict locked workspace/all-targets
Clippy pass; full workspace requalification is pending.

This establishes source authority for a proposal under the supplied trusted
base. It does not authorize active revision or checkpoint publication. Private
namespace/Git joins, coding receipts, retention/quota policy and rechecking both
the checkpoint base and current certified guild-event membership/writer fences
remain mandatory. A concurrent rotation/removal may supersede the base without
changing its checkpoint hash. A paged checkpoint authority constructor and
normal capture/packing/coding/checkpoint/retention/seed-only consumer migration,
incremental edits, real retained 1 TiB and release/platform gates remain open.

Exact-source qualification on `b509ac4`: the locked workspace passes 935 tests,
zero failed, 116 ignored, including all 418 ordinary Node and 166 ordinary store
tests. The corrected mixed packed-group fixture passes in the workspace run.
The locked workspace/all-targets test build passes. Provisioned retained native
Btrfs migration/recovery passes in 29.68 seconds. All 236 tracked-file and both
workspace test-binary hashes match before/after native recovery; runner cleanup
and independent mount/loop/namespace/disposable-directory checks pass. This
supersedes the pending workspace requalification above. It does not diagnose
the original R5 stall or qualify release artifacts, other platforms or real
retained 1 TiB data.

### Ordered paged checkpoint authority records (2026-10-07)

The public guild `Checkpoint` page section appends discriminant five, preserving
all existing page/record layouts. `CatalogCheckpointAuthorityBuilder` and its
reader stream bounded members, writer fences, retained tombstones, mixed legacy
and paged revisions, owner bindings and epoch attestations. Records decode
within 4 KiB, roots within 1 KiB, signatures within 64 bytes and member domains
within 256 UTF-8 bytes. At most 256 members are accepted. Phase/key order,
contiguous writer epochs, consecutive revisions within each chain, exact parent
hashes, nondecreasing writer epochs, individual signatures and exact EOF counts
are checked with constant catalog state.

Legacy revision records reference the original signed canonical envelope in
bounded public byte pages. `CatalogLegacyRevisionRef` binds the guild, owner,
root/revision IDs, sequence/parent, writer fence and original body hash. Reading
it authenticates every referenced byte page, applies the unchanged 32 MiB old
per-object cap, verifies both original signatures, source geometry and exact
summary, and preserves original signed bytes for formats 3/4/5. Legacy decoding
retains one bounded old envelope and its existing per-object allocations; it
does not collect every retained revision. New paged revisions retain their
bounded signed source roots. A reference header alone cannot authorize a source.

The typed authority root counts the control stream, its fixed descriptor, every
legacy envelope and every referenced paged source closure against the existing
aggregate byte/page limits. Duplicate source-root references count repeatedly,
so this accounts for traversal rather than deduplicated physical storage. This
is authority-stream admission, not the complete packing/coding/checkpoint
capacity policy or the retained-data quota. The local packing candidate cursor
now uses the same owner/root/sequence/UUID order, with a fixed big-endian indexed
key. Reversed UUID order cannot reorder a signed chain or require a whole-catalog
sort before constructing the checkpoint authority stream.

Qualification: all 140 core and 166 ordinary store tests pass (26 store tests
ignored); formatting/diff checks and strict locked workspace/all-targets Clippy
pass. Six new core fixtures cover all three legacy formats with original
signatures/identities, 1,000 chained paged revisions across multiple pages,
retained tombstones, 256-member/domain boundaries, malformed nested signature
lengths, wrong phase/chain/fence/evidence, aggregate budgets, corrupt tails,
failed sinks, complete legacy byte traversal and failure fencing. A deterministic
55-byte protocol root vector binds mixed records and both evidence variants.
The store fixture directly feeds checked candidates with reversed UUID order
into the mixed authority builder and reads its original legacy envelope back.
The earlier full workspace/native qualification belongs to `b509ac4`; it is not
new runtime evidence for this codec.

This codec does not issue a paged checkpoint certificate or activate a consumer.
Complete membership/current guild-event fence authorization, retained-prefix
tombstone and global revision-ID joins, every source/bootstrap EOF and migration
evidence quorum remain mandatory. Durable ownership must follow logical root
references inside records as well as byte-tree children; publishing only the
authority byte-tree root cannot retain its legacy/source closures. Enclosing
certificate/coding codecs, that ownership/retirement path, normal
capture/packing/checkpoint/retention/seed-only migration, incremental updates,
quotas and real retained 1 TiB/release/platform qualification remain open.

### Durable public authority-root retention (2026-10-07)

`CatalogCheckpointRetention` gives local SQLCipher ownership to the logical
roots embedded in checkpoint authority records. The existing fixed bundle
holds at most sixteen roots; an authority stream can reference many more legacy
envelopes and paged source trees. Byte-tree parent edges alone cannot preserve
these references. The new journal pins its authority tree, each original legacy
envelope tree in the guild Checkpoint scope, and each signed source tree in its
dataset SectorReferences scope. All dependencies must belong to the same guild;
private metadata is excluded from this public journal.

The immutable descriptor and counters occupy one record bounded to 2 KiB.
Dependencies are individually bounded to 256 bytes and indexed by root hash;
there is no in-memory root collection. A separate seventeen-byte pin key cannot
alias existing sixteen-byte capture pins, even when job and capture UUIDs match.
Each root acquisition checks the local authenticated root and commits its pin,
dependency and checked counters in one short writer transaction. Existing page
parent links retain its immutable child closure. Full traversal runs without a
held writer transaction. The typed authority reader checks complete ordered EOF;
each legacy reference authenticates and verifies its original signed envelope;
each paged source reader checks complete records and its declared bootstrap
entry. Only then does a final checked state transition publish local retention.

Interrupted Building jobs replay the same immutable descriptor from the start
after reopening. Repeated roots share one dependency within a journal, while
the signed root's aggregate bounds still count repeated traversal work. Separate
journals hold independent pins. Failed traversal/publication fences a still
Building job before cleanup; a concurrent successful replay is not retired by
the failed worker. Cancelled IDs never resume. Retirement first fences further
acquisition/publication, then releases at most one root in each transaction.
Ordinary page GC preserves every remaining capture, checkpoint and parent owner.
Counters and state use compare-and-swap with readback; ignored acquisition,
publication and release writes fail without advancing partial ownership.

Six focused fixtures pass. They cover 97 distinct roots, shared source roots
across consecutive revisions, multi-page legacy/source trees, capture/journal
UUID collision, original capture-pin release, independent shared journal
ownership, reopen during build and retirement, invalid legacy signatures,
missing bootstrap entries, corrupt authenticated tails, fresh publication after
an ignored completion write, ignored acquisition/release rollback, orphan and
oversized records, foreign guilds and private-scope rejection. All 140 core and
172 ordinary store tests pass (26 store tests ignored), with strict locked
workspace/all-targets Clippy and formatting/diff checks. The earlier complete
workspace/native qualification still belongs to `b509ac4`; no new native,
network, release-artifact or real retained 1 TiB result is implied by these
local ownership checks.

This journal preserves public metadata bytes locally. Bootstrap ciphertext,
native source anchors/data, private roots and coding witnesses retain separate
ownership requirements. A production checkpoint must join the complete current
guild-event authority, tombstones, globally unique revisions and evidence quorum,
and protect current checkpoint retention from retirement. Enclosing certificates,
coding roots, normal capture/publication/retention/seed-only consumers, shared
quotas and real retained 1 TiB/release/platform qualification remain open.

### Fragmented original coding evidence (2026-10-08)

`CatalogCodingBuilder`/`CatalogCodingReader` stream original signed variable
coding transcripts through the public guild Coding section. A group header
contains version one, its original group ID, added/retired/retain-through event
positions, the unchanged BLAKE3 hash of its signed canonical transcript, and
the transcript byte length. Exact contiguous fragments follow, bounded to
16 KiB each. The complete original group descriptor already appears in its
signed manifest, so the header does not duplicate its roles/domains. One decoded
group and original witness are retained at a time, followed by existing full
signature, commitment, challenge, receipt, opening and sampled-RS replay.
Every replay result must be Verified. Signature validity or authenticated
pages alone cannot authorize the group or its lifecycle.

Each signed transcript is bounded to 600 KiB, covering the original peer-bounded
evidence, including full-byte compatibility witnesses. New bounded decoders
limit every outer/nested signature to 64 bytes, receipts/openings and role
collections to 64, domains to 256 bytes and sampled openings to their existing
one-leaf geometry before allocation. Existing legacy decoders and original
signed layouts/identities remain unchanged. Transcript replay retains its
existing fixed per-object allocations; 600 KiB is the encoded-object ceiling,
not a claim about peak replay memory.

The root directory has at most four existing 16 GiB record trees, a 512-byte
descriptor, exact group/retired/information/parity/witness/fragment counters,
and a guild event sequence. Groups are globally unique and ordered by original
ID across parts. A group cannot cross a part boundary. The directory shares a
64 GiB represented-byte ceiling, including itself, and the existing aggregate
one-million-page occurrence limit; records across parts share the 64-million
record cap. Primitive byte-tree and peer-frame limits are unchanged. Empty
forests carry no pages. Final summaries, every fragment offset/length, both
typed/raw EOFs, canonical encodings and original witness hashes are mandatory.
Builder/reader errors fence subsequent operations.

The existing single-tree 16 GiB ceiling cannot contain the default dense coding
evidence. A coding-only structural sizing fixture uses a real compact 3+2,
64 KiB transcript with maximum 256-byte domains and integer-width charges,
including worst-case sampled-leaf varints. For a dense 1 TiB information input,
5,592,406 groups fit at 47,390,048,988 represented bytes and at most 777,414
page occurrences. It counts frame, directory, stream and
conservative leaf/index occurrence overhead. This does not admit an additional
64 GiB independently of other checkpoint sections. Combined authority/packing/
public/private-source admission, logical retained-data quotas and real 1 TiB
memory/work/runtime qualification remain required before activation.

`CatalogValidatedCoding::verify` requires complete replayed EOF and an external
authorization callback for every group. The callback must join certified
delegation/membership/domains, source/packing coverage and retained lifecycle
authority using read-only state or a disposable job. Only the completed token
can produce a local bundle binding precisely all parts in directory order.
The existing atomic journal rechecks all intents and retains every byte-tree
closure across reopen and shared owners. Cancelled parts cannot publish a
prefix. Empty forests need no separate pin bundle and travel in the enclosing
descriptor. Current authority must still be rechecked for protocol activation;
this local token does not certify protection or own native/parity payloads.

Nine core fixtures and two store fixtures cover all three original attempt
versions, original signed bytes/group IDs, full-byte witnesses crossing pages,
64 compact groups sharing one tree, four-part global order, malformed fragment
offsets/lengths, incomplete/cross-part groups, corrupt tails, false coding
evidence, rejected caller authorization, scope/lifecycle/counter limits, failure
fencing, four-root atomic publication, sharing, reopen and cancelled-part
rollback. A 179-byte directory vector and original four-transcript vector bind
the new layout and old witness bytes. All 149 core and 174 ordinary store tests
pass (26 store tests ignored), with strict locked workspace/all-targets Clippy
and formatting/diff checks. These are codec and local ownership checks; the
earlier full workspace/native qualification belongs to `b509ac4`, and no new
network, provisioned native, release-artifact or retained 1 TiB runtime result
is implied here.

Fixed legacy `CodingGroup` records remain on their unchanged legacy certificate
path; this codec preserves variable `CodingGroupV2` evidence and does not
reinterpret fixed group IDs. Their migration, enclosing paged certificates,
complete authority/source/coding joins, current checkpoint retirement guards,
normal capture/coding/publication/retention/seed-only consumers, incremental
work, combined quotas and real retained 1 TiB/release/platform gates remain open.


### Bounded packing/coding coverage (2026-10-08)

The disposable packing index now retains a fixed completed-sector summary only
when its original ID, full source composition and Merkle commitment have passed.
The global packing completion marker still follows both typed EOFs. Coding joins
reuse that same physically admitted encrypted index and its 1 MiB cache; they do
not materialize the packed catalog or hold a production SQL writer while fetching
and replaying evidence.

`CatalogPackingIndex::validate_coding` requires full coding-forest EOF and an
external certified-history authorizer for every original witness. It joins each
information role to the verified packed summary: original ID, exact commitment,
full logical length, shard size and signed plan root. Every current packed sector
must have eligible active coverage before the combined completion marker exists.
Virtual information/filler and retired groups never establish coverage. Multiple
active replacement groups may cover an input; the index selects the first eligible
group in canonical ID order and retains all original witnesses. Historical groups
outside the current packing remain available under the required authorizer.
Unbound original attempt-one witnesses remain retainable but cannot cover inputs.

Current and historical coverage policies are explicit. A CurrentPlacement result
from the authorizer certifies current membership/domain placement in addition to
original delegation and retained lifecycle authority. Retained authority alone
cannot cover a current checkpoint. Current flat-root inputs require the existing
full-byte attempt-three witness; historical lookup preserves original compact
flat-root evidence. The authorizer must bind the certified guild event head,
original add/retire events and original witness hash, and use read-only state or
a disposable job. Current authority must be rechecked at protocol publication.
This API supplies the packing/coverage join rather than delegating that join to
the callback; certified guild history and lifecycle validation remain mandatory.

The combined fixed descriptor, both packing streams and all coding parts share
one 64 GiB represented-byte ceiling and one million page occurrences. The
certified-source wrapper also carries forward all admitted legacy envelope,
paged-source/candidate and migration-evidence work, plus its trusted base and
bounded candidate cursor. The earlier authority/packing bridge retains its own
conservative 16 GiB admission. Neither primitive tree nor peer-frame limits
change. This aggregate accounting does not derive retained dataset/file/Git
quotas or qualify the complete enclosing checkpoint capacity.

Full traversal records a fixed local cursor containing part, byte offset, framed
length, original group ID and original witness hash. Original record bytes and
protocol vectors remain unchanged. Range reads authenticate only intersecting
pages, decode/replay one original witness and verify its exact range and identity.
They do not establish whole-forest EOF, ordering or coverage; their trusted source
is the completed disposable index. Recovery lookup thus needs no whole-catalog
scan. Fixed bounded index records also retain lifecycle and coding profile.

Only the completed combined proof can bind both packing roles and all (at most
four) coding parts in one ordinary atomic local bundle. Cancelled final parts
cannot publish packing alone. Shared successors preserve all six closures across
reopen; bounded pin retirement and ordinary page GC reclaim them after the last
owner. This local bundle does not issue a certificate or own native/bootstrap,
information or parity payloads.

The full locked regression passes all 150 core and 182 ordinary store tests
(26 store tests ignored). The final additional local-cursor corruption fixture
and two expanded packing/sector fixtures pass separately. Formatting/diff checks
and strict locked workspace/all-targets Clippy pass. The original overlapping
rebuild removed an older test executable before two subprocess fixtures could
launch; both pass in the completed rebuilt suite. No new network/native/release
or real retained 1 TiB runtime qualification is implied. The fixtures cover original witness seek/replay, malformed cursors and scopes,
full-byte compatibility, omissions/substitutions, virtual/retired coverage,
replacement overlap, unrelated retained groups, explicit historical/current
placement, ignored-write and late-fetch/authority rollback, aggregate admission
before fetch, real spill beyond the cache, index exhaustion/fresh rebuild,
certified base/candidate/accounting continuity and six-root durable ownership.
The enclosing paged certificate, current guild-event/lifecycle authority join,
fixed legacy-group migration, guarded retirement, normal capture/coding/
checkpoint/retention/seed-only consumers, quotas, incremental work and real
retained 1 TiB/release/platform qualification remain open.


### Single-owner metadata capacity shortfall (2026-10-08)

A focused audit after `cbb78bd` checks the existing stable-slot allocator as well
as canonical codec sizes. With four 16 KiB slots per 64 KiB sector, one owner
leaves one slot reserved for a future different owner. Three dense source
sectors therefore produce four packed sectors, as an actual allocator fixture
verifies. The earlier fully occupied coding-only sizing result remains valid
for its stated information-input geometry; it does not describe the packing
required by a single protected dataset's one-owner sources.

For 1 TiB of dense data source sectors, this policy needs 16,777,216 sources,
22,369,622 packed sectors and 7,456,541 default 3+2 codewords. A real compact
witness with the supported 256-byte certified domains supplies the codec size.
Subtracting all three maximum-width u64 expansions and all five possible
sample-index expansions yields a necessary 8,415-byte lower bound per group
for this supported witness family. This gives 62,746,792,515 coding bytes and
at least 1,021,270 coding leaf occurrences, without stream/index/root overhead.
The current coding forest's one-million-page aggregate ceiling cannot admit
that shape even though its four primitive 16 GiB byte trees can hold the bytes.

Canonical compact descriptors (using minimum-width sector indices and allowing
for the final partially occupied sector) add at least 7,046,430,806 bytes;
complete-source headers/subtrees add 4,596,957,192 bytes. Together these sections
already require at least 74,390,180,513 represented bytes, exceeding the staging
join's 64 GiB combined ceiling. Signed public source trees, encrypted private
recipes/namespace pages and their coding inputs, bootstrap/control records,
retained revisions, Git history and replacement witnesses are still excluded.
The calculation extrapolates allocator/codec geometry; it does not materialize
or qualify an actual 1 TiB capture, producer, recovery or retained dataset.

`single_owner_dense_one_tib_requires_more_than_one_million_coding_pages` pins
this necessary lower bound without requiring that future admission keep the
current limitation. Its focused test, formatting/diff checks and strict locked
workspace/all-targets Clippy pass. Primitive and signed layouts remain unchanged. R3-SINGLE-OWNER-METADATA remains open: the enclosing policy
and directories must admit the required dataset geometry, account for every
section and retained owner, and declare dataset/file/history/guild limits.
Raising parser constants alone, assuming unrelated owners fill the reserved
slots, or relying on the isolated fully occupied sizing fixture does not resolve
that requirement. Normal producers remain gated on that complete design and
runtime qualification.

### Coding directories and durable logical forest ownership (2026-10-08)

A new fixed-size `CatalogCodingDirectoryRoot` authenticates an ordered record
stream of existing `CatalogCodingRoot` descriptors. Each original forest keeps
its four-part, 64 GiB and one-million-page limits; primitive byte trees keep
their existing limits. Original group identities, signed witness bytes, record
variants and forest protocol vectors remain unchanged. The directory producer
rolls forests conservatively before one dense 16 GiB tree fills, keeping bounded
producer state. The directory itself remains one bounded record tree rather
than allocating a catalog-sized vector.

Every public directory decode, builder, reader and group lookup requires a
trusted enclosing byte/page/record budget. The caller must charge other
checkpoint sections before supplying the remaining budget; copying limits from
an untrusted peer is not admission. Work includes a fixed 512-byte root charge,
the directory's framed descriptors and every referenced part occurrence.
Repeated references are charged again. Descriptors are already in the directory
stream and are not charged a second time as separate envelopes. Budgets never
reset at forest boundaries, checked arithmetic rejects overflow, and declared
work is admitted before any fetch. Conservative producer reservations can reject
a group before its exact final encoding would fill the limit.

The complete reader decodes bounded original descriptors, checks cumulative
summaries before fetching their evidence, replays every original witness,
checks global group ordering across forests and requires all nested and
directory EOFs. A fixed group location carries the original part reference and
range. Point reads authenticate intersecting pages and replay one witness;
they require a location from a trusted completed traversal and do not prove
global membership, EOF, authority or packing coverage independently.

Logical part references inside directory records are not byte-tree child
edges. Ordinary ownership of the directory root alone would lose those parts.
`CatalogCodingRetention` therefore uses fixed journal/dependency records and
short per-root writer transactions. Its reader hook pins each structurally
admitted forest before evidence fetch, then publishes metadata ownership only
after complete replayed ordered EOF. Crash-interrupted Building jobs replay
idempotently; failures fence jobs; cancelled cleanup releases one root per call.
Independent journals share immutable roots, and their pin prefix differs from
both 16-byte capture IDs and authority-retention jobs. Traversal charges logical
occurrences while ownership counters charge distinct physical roots. Existing
byte-tree parent links preserve descendants until the last owner retires.
Staging may use multiple existing bounded intents; this does not increase any
single intent's page limit.

The focused fixtures cover twelve forests, four-part compatibility, multi-page
full-byte witness lookup, a directory with 1,024 descriptors, malformed nested
roots, before-fetch admission, budget exhaustion after several forest boundaries,
ownership callback cancellation, exact summaries/order/EOF and a new fixed
protocol vector. A structural large-closure fixture exceeds the old single
forest's byte/page ceilings while retaining each original forest's limits; its
missing evidence deliberately fails full replay. This is not a materialized
large-data or retained 1 TiB qualification. Store fixtures cover 21 distinct
roots beyond fixed bundle capacity, shared successors, build/cleanup reopen,
original capture-pin retirement, late duplicate/corrupt evidence, ignored
acquisition/publication/release writes, scopes, orphan rows, exact job/budget
binding, empty directories and disjoint pin namespaces. Deliberately corrupted
page bytes are repaired in the fault fixture before GC, whose existing
integrity checks correctly reject unsafe reclamation of damaged pages.

The existing completed packing/coding index still consumes one original forest
and retains its conservative combined admission. Joining directories into that
index and the full authenticated checkpoint remains required. This codec and
local journal do not derive the complete dataset/file/extent/Git/history/guild
policy, own information/parity/native/bootstrap payloads, certify current
membership/delegation/lifecycle, guard active checkpoint retirement or enable
normal consumers. R3-SINGLE-OWNER-METADATA and the enclosing production,
retained 1 TiB, release and platform gates remain open.

Validation: the full locked combined regression passes 160 core and 189 ordinary
store tests (26 store tests ignored). The final core run passes all 161 tests,
including the fixed-vector assertion and the added understated-summary fixture,
which verifies rejection before the affected forest's ownership hook or evidence
fetch. Strict locked workspace/all-targets Clippy, formatting and diff checks
pass. No network/native/release or real retained 1 TiB runtime gate was rerun
for this codec and local ownership slice.

### Directory packing coverage and shared authority admission (2026-10-08)

`CatalogPackingCodingDirectoryIndex` joins the complete coding directory to the
already completed packing index in the same admitted encrypted scratch store.
It requires complete replayed nested/directory EOF, external authorization of
every original witness and exact eligible active coverage for every verified
packed input before its completion marker exists. Both forest and directory
joins use the same coverage rules: exact commitments/geometry/signed roots,
no virtual or retired coverage, explicit current versus historical placement,
and full-byte witnesses for current flat-root inputs. Overlapping replacements
and unrelated retained history preserve their original witnesses. Fixed index
rows add the original part reference to the existing bounded group metadata;
point reads authenticate and replay one witness without a directory scan.

The new local descriptor requires a trusted byte/page/record budget separately
at decode and construction. It charges one fixed 4096-byte combined envelope,
both packing streams, directory frames and all original evidence occurrences.
The directory's existing 512-byte root reservation is part of that envelope,
not an additional duplicate charge. Packing and already admitted authority work
are debited before the directory reader is constructed. Checked addition and
subtraction reject overflow/exhaustion before fetch. The standalone packing API
requires the caller to debit any external authority/other sections first; the
certified source wrapper carries and debits its own prefix automatically.

`CatalogCertifiedCodingDirectoryIndex` preserves the trusted legacy source base
and complete signed candidate cursor across the join. Prefix bytes/pages retain
their existing accounting. Its new record ledger counts one bounded legacy
certificate, each signed paged candidate or migration evidence object, and every
framed paged-source record occurrence. Repeated source roots count again even
when the disposable source table deduplicates their physical identities. This
ledger does not count fields inside the already bounded flat certificate as
separate framed records or make that legacy verifier scalable. Current certified
guild-event/lifecycle authorization and publication fences remain external.

The original single-forest API, serialized local descriptors/index rows and
signed protocol bytes remain unchanged. Both join paths reject orphan state in
either namespace. Ignored inserts and all late fetch/order/summary/authority
failures roll back the entire directory join, preserving the admitted packing
proof. The directory path allocates no second scratch store and keeps fixed
bounded local rows and one decoded witness at a time.

Focused fixtures cover 15 forests, overlapping/retired/unrelated groups, exact
witness seek, missing/virtual/retired/unbound coverage, historical/current
placement, empty inputs, every budget dimension and prefix debit, overflow,
malformed cursors, ignored writes, both namespace orphan directions and late
failure after valid prefixes. A 768-source/256-forest fixture spills past the
1 MiB cache, fails at the admitted storage limit without a usable prefix, and
rebuilds in a fresh admitted index. The certified-source fixture verifies the
original base/candidate cursor, exact three-dimensional prefix continuity and
budget rejection before fetch; existing evidence/repeated-candidate fixtures
also pin the new record ledger.

A structural fixture uses the single-owner audit's necessary 1 TiB source,
packed-sector and group geometry. The combined local descriptor admits its
necessary byte/page/record counts under an explicitly supplied budget even when
bytes/pages exceed the old combined ceilings and aggregate records exceed one
original tree's record cap. The previous combined join had no separate aggregate
record ceiling; the new required record budget is explicit. Its references and summaries are
synthetic and represent lower bounds, not a complete upper-bound policy or a
completed packing/coding proof. It does not materialize or qualify large data.
The full dataset/file/extent/Git/history/guild policy, retained quota reservations
and normal consumers remain required under R3-SINGLE-OWNER-METADATA.

This completed disposable proof activates no checkpoint and owns no durable
payloads. The separate coding-retention journal can own the directory's logical
forest roots, but the enclosing checkpoint owner must bind those dependencies
and both packing roots with certified-current guards. A fixed ordinary bundle
containing only the directory and packing roots would omit logical forest
ownership. Composite authority/packing/coding/private and payload ownership,
full paged certification, normal capture/retention/seed consumers, incremental
work and all retained 1 TiB, release and platform gates remain open.

Validation: all eight focused directory fixtures and the expanded certified
source/coding fixture pass. The full locked regression passes all 161 core and
197 ordinary store tests (26 store tests ignored), including both existing
forest joins and durable authority/coding ownership. Formatting/diff checks and
strict locked workspace/all-targets Clippy pass. No network/native/release,
other-platform or real retained 1 TiB runtime qualification is implied by this
staging index and accounting change.

### Completed directory proof and combined local metadata ownership (2026-10-08)

`ControlStore::retain_catalog_packing_coding` now accepts a completed
`CatalogPackingCodingDirectoryIndex`, binding its exact immutable manifest and
trusted byte/page/record budget into one durable local journal. A descriptor
alone cannot start or resume this operation. The completed packing and directory
markers are required before acquisition and again before publication. A reused
job ID must match both manifest and budget exactly; cancelled IDs never resume.

Both packing byte-tree roots and the coding-directory byte-tree root acquire
their pins in one short transaction. Initial failures roll back the journal and
all three roles. The subsequent typed source and descriptor readers require full
authenticated local EOF; compact descriptors resolve original source identities
through the already completed admitted index. The directory reader pins each
bounded forest's logical part roots before evidence reads, replays original
witnesses, and requires every nested and globally ordered directory EOF before
publishing the journal. These traversals hold no production database writer and
allocate no catalog-sized root vector or second scratch index. Original staging
owners must survive until successful publication.

Crash-interrupted Building jobs replay idempotently with a rebuilt equivalent
completed proof. A traversal or publication failure cancels only a still-Building
job; it cannot cancel another worker's completed publication. Cancelled cleanup
releases one authenticated dependency, pin and counter update per transaction,
with ordinary bounded page GC following the byte-tree edges. Independent
successors retain shared roots after predecessor cleanup and capture retirement.
The new 17-byte pin namespace uses prefix three, distinct from authority and
coding journals and from 16-byte capture IDs.

The authority, coding and combined owners now share the bounded journal's
canonical read, exact descriptor binding, pin/dependency readback, counter CAS
and incremental cleanup code. Existing version-one authority/coding journal and
dependency layouts, namespaces and pin prefixes are preserved. Independent
copies of the original journal enum and field order verify all three state
encodings and decode compatibility. Per-policy walkers and scope restrictions
remain separate.

Traversal admission still charges every logical occurrence, including repeated
roots and the previously admitted authority prefix. Ownership counters charge
distinct packing/coding root closures. They exclude authority work, which this
owner does not acquire. In the empty case the identical two packing roots share
one physical pin while all three logical top-level occurrences remain charged.
This does not increase any original tree, forest, staging-intent or fixed bundle
limit, or derive the enclosing retained dataset/file/history/guild quota policy.

Six combined-owner fixtures cover 23 distinct roots beyond fixed bundle
capacity, original capture retirement, shared successors, acquisition and
cleanup reopen, rebuilt proofs, budget substitution, carried authority work,
empty-root deduplication, incomplete markers, orphan/scope rejection and all pin
namespaces. Ignored counter, pin, dependency, publication and cleanup writes
cannot expose partial ownership. A 384-source/128-forest fixture corrupts late
local source/descriptor leaves below valid pinned roots and the final logical
coding root; each attempt fails without publishing a prefix. Fault bytes are
repaired before ordinary authenticated GC is exercised.

This is one combined local packing/coding metadata owner. It does not certify
current guild-event membership, writer fences or coding lifecycle, own authority,
owner-private/native/bootstrap metadata or information/parity payloads, activate
a checkpoint, or guard retirement of a certified current checkpoint. The
enclosing checkpoint must bind those remaining owners and publication/retirement
guards; independent journals alone do not establish that guarantee. The parent
checkpoint-ownership TODO, R3-SINGLE-OWNER-METADATA, normal capture/retention/seed
consumers and all retained 1 TiB, release and platform gates remain open.

Validation: all 20 focused authority/coding/combined retention fixtures pass.
The full locked regression passes all 161 core and 205 ordinary store tests
(26 store tests ignored), including the expanded carried-prefix and atomic
initial-failure checks. Strict locked workspace/all-targets Clippy and
formatting/diff checks pass. No network/native/release, other-platform or real
retained 1 TiB runtime gate was rerun for this local ownership slice.

### Complete public authority joins into packing and coding (2026-10-08)

`CatalogCheckpointAuthorityIndex` now validates the complete mixed authority
stream in an admitted encrypted scratch store. Unlike the existing migration
bridge, it does not first materialize a flat legacy checkpoint. Its authenticated
authority root and separately supplied `CatalogCheckpointAuthorityContext` bind
the guild, intended generation, certified event sequence/head, membership epoch
and quorum policy. The context and exact active member slice must come from
independently certified guild history, never from the proposed root's own claims.
Every decoded member must match that slice, including recovery keys and failure
domains. A mandatory writer callback verifies every historical fence and each
owner's latest retained fence against the same event snapshot. Removed owners
may retain previously authorized history; this does not authorize a new mutation
by a removed owner or replace comparison with the previous checkpoint.

Mixed legacy and paged chains now join their first retained revision to sequence
one or an exact tombstone suffix. Later revisions retain contiguous sequence,
parent hash and nondecreasing writer epochs. All listed latest fences need a
retained head, and every tombstone needs a retained suffix. The disposable global
ID table reserves both retained revision IDs and tombstones' last retired IDs,
rejecting reuse across owners, roots or formats. Every revision's writer epoch
and key must match an admitted historical fence. Legacy envelopes retain their
original signatures, identities and individually bounded decoding; paged sources
require complete authenticated EOF and the exact signed bootstrap sector.

The source table joins repeated references without weakening identity or
geometry. A global object-ID index rejects cross-owner/root reuse and changed
logical lengths or flat roots. Merkle commitments must agree across retained
references; an initially uncommitted legacy source can gain its commitment from
an exact signed paged source, owner binding, or current-epoch quorum attestation.
Migration evidence must name a retained source and its exact flat root and
commitment. Redundant/unusable evidence and incomplete current-member tallies
fail the join. An identity's public `validate` method checks shape only; signed
source authority and eventual payload verification remain separate requirements.

One required trusted byte/page/record budget survives authority, packing and
directory construction. Authority work reserves a fixed 2048-byte descriptor,
control pages and every legacy/source closure occurrence. The record ledger
charges authority frames, each separately decoded legacy envelope, every flat
legacy source entry and every paged-source frame, including repeated trees.
This ledger is explicit for the new streaming authority path; the older bounded
legacy-certificate bridge retains its existing accounting. Declared nested
paged-source records are admitted before fetching source pages; legacy entries
are admitted after their bounded envelope decode and before indexing entries.
Bytes/pages are admitted from the authority root before traversal.

The core authority reader now compares every cumulative summary dimension with
the root's declaration before returning a record. An understated nested byte or
page summary therefore cannot expose a body reference whose fetch would exceed
the enclosing admission. Exact final EOF checks still apply. This strengthens
validation without changing any existing root, signed envelope or protocol
vector layout. Original per-tree, forest and authority-root caps remain intact.

`CatalogCheckpointPackingIndex` joins exactly all authenticated retained sources
to both packing streams in that same scratch store. The directory join debits
the complete authority work, binds the event sequence, replays all original
witnesses and establishes exact eligible packed-input coverage under the shared
budget. `CatalogCheckpointCodingDirectoryIndex` preserves the authority
descriptor and bounded mixed-revision cursor. Cursor reads require completion,
check original keys, scope and signatures, and never scan or materialize the
whole retained revision/source set. Source rows, original legacy references,
and signed paged revisions retain their bounded schemas. Existing legacy-base
source-authority APIs and serialized layouts remain unchanged.

All authority acquisition uses one private scratch transaction; no production
database writer spans traversal or external callbacks. Ignored writes and late
authorization, framing, bootstrap, page or summary failures produce no completed
index. Failed jobs discard their scratch store and rebuild. Completion remains
mandatory after the packing/coding join as well. This is not a quorum-signed
paged checkpoint, a certified transition or a publication/retirement guard.
Current event rechecks, historical coding lifecycle/delegation, fixed legacy
coding migration, owner-private/native/bootstrap joins and information/parity
payload custody still need the enclosing checkpoint. Full admission/quotas,
normal producer/retention/seed consumers and all retained 1 TiB, release and
platform gates remain open.

Validation: all eight focused store fixtures pass, as does the new core check
for understated nested work before reference exposure. The full locked
regression passes 162 core and 213 ordinary store tests (26 store tests ignored).
Fixtures exercise exact mixed/source cursors, tombstones and retired IDs,
historical/latest authorization, removed owners, source geometry conflicts,
owner/quorum evidence, before-fetch rejection in every budget dimension,
ignored writes, orphan markers, missing bootstrap, corrupted cursors and a late
control-page failure across 162 mixed revisions. A 4,098-source metadata fixture
spills beyond the 1 MiB cache, exhausts a smaller admitted store and rebuilds;
it does not materialize or qualify large payload data. Strict locked
workspace/all-targets Clippy and formatting/diff checks pass. No network/native,
release/platform or real retained 1 TiB runtime gate was rerun for this join.

## Paged public quorum headers bind the completed proof (2026-10-08)

A separate `PagedGuildCheckpoint` format eight now binds the completed public
checkpoint proof without materializing a flat legacy checkpoint. Its fixed
4 KiB header contains guild/genesis, generation and original predecessor hash,
certified event sequence/head and epoch/quorum, the original authority root and
complete authority record ledger, both packing roots and the coding directory.
The public header contains no owner-private plaintext root hashes. Legacy
checkpoint formats 3–7, signed revision/evidence layouts and hashes are unchanged.
New header signatures use `mutualbackup/paged-guild-checkpoint/v1`; body identity
uses the BLAKE3 derive-key context `mutualbackup paged guild checkpoint body v1`
and excludes the collected signer subset.

`QuorumPagedCheckpoint` is bounded to 32 KiB and 256 strictly ordered distinct
active-member signatures, each exactly 64 bytes. Its nested decoder rejects
oversized list/signature declarations before allocating their bodies. Header
verification requires a separate `PagedCheckpointTrust` snapshot containing the
independently certified event roster/quorum and exact trusted previous state.
That local trust type deliberately has no wire decoder. Trust bounds validate
member keys, recovery keys, bounded domains and ordering before quorum replay;
no trust is learned from the proposed root. Parent identity/generation, genesis,
event head/sequence and policy must match exactly. The unchanged previous hash
can refer to a legacy checkpoint. Header/quorum verification alone establishes
neither full body EOF nor a legal previous-state transition.

The original trusted proof budget admits one fixed 32 KiB certificate envelope
plus every public byte/page/record occurrence. This replaces the 2048-byte
local authority and 4096-byte local combined descriptor reservations, adding
26,624 bytes to that completed local ledger without changing page/record debt.
Embedded directory/packing/root descriptors are not charged again. The exact
authority record count includes nested paged frames and flat legacy source
entries; the core checks its declared bounds and the store bridge requires its
exact equality to the completed proof. Existing tree/authority/packing caps
remain intact, and all coding forests share this original budget. This is not
a complete retained-history quota or private/payload admission policy.

The original public-body signing bridge (strengthened by the transition proof
below) requires
current coverage and every authority/packing/coding completion marker. Full
original member records now have bounded disposable rows so it can recompare
recovery keys and domains, as well as IDs, with the independently read roster.
The supplied callback rereads certified event state and the trusted predecessor
before and after the operation; changed/error snapshots or missing completion
and member rows fail closed. The final check rereads the bounded member rows as
well as markers. No production writer spans traversal or callbacks.

`bind_paged_checkpoint_header` requires the exact original roots and authority
ledger plus an independently valid current-member quorum, and returns a private
`CatalogQuorumPagedCheckpointIndex` preserving the original certificate, trust
snapshot and complete indexed body/cursors. Cryptographically valid substituted
roots or record counts cannot acquire this wrapper. Its later `recheck_header`
checks the same exact live snapshot and proof again. Historical coverage cannot
sign or bind a current checkpoint; a removed owner can retain authorized history
but cannot sign a new current-member header.

These are explicitly draft public header APIs with no normal producer or
production publication/retirement capability. Full previous-state omission,
retention and current-candidate writer rules, original coding lifecycle and
fixed legacy-group migration, private/bootstrap/native and information/parity
payload custody, complete durable ownership, atomic certified-current guards,
full quota policy and all retained 1 TiB/platform/release gates remain required.
The enclosing checkpoint TODOs remain open.

Seven core fixtures cover deterministic header/quorum bytes, distinct legacy
signing domains, stable signer-subset identity, exact independent event/base
trust, malformed/duplicate/nonmember signatures, before-allocation list limits,
noncanonical/trailing bytes, all three admission dimensions and arithmetic
bounds. A real authority builder with 256 members and 256-byte domains confirms
that the full unanimous quorum fits the envelope. Six store fixtures construct
real mixed legacy/paged sources, packing and full-byte coding witnesses. They
cover exact proof/cursor preservation, quorum-valid root/ledger substitutions,
current/historical/removed-owner rules, changed/error trust callbacks, exact
certificate-envelope admission and missing completion/member rows. The new
member namespace also joins ignored-write and orphan rejection coverage.

Validation: the full locked regression passes all 169 core and 219 ordinary
store tests (26 store tests ignored). Strict locked workspace/all-targets
Clippy and formatting/diff checks pass. No network/native, release/platform or
real retained 1 TiB runtime gate was rerun for this header bridge.

## Public authority transitions gate paged header signatures (2026-10-08)

`CatalogCheckpointTransitionIndex` now compares a completed public proposal
against its exact independently trusted previous checkpoint before paged header
signing/binding. `CatalogCheckpointPrevious` accepts a bounded original legacy
certificate with separately certified historical event/epoch trust, or an
already completed quorum-bound paged predecessor. The expected generation/hash
comes from the new independent current snapshot, never from the same proposed
input. First checkpoints require no predecessor. Legacy formats 3–7 retain their
original signatures and body hashes; formats 3/4 require the supplied historical
authority witness. Paged input retains its original certificate and completed
public body/transition proof. No raw manifest/header can acquire either proof.

The complete authority index records fixed revision facts alongside each original
mixed record. Facts bind the owner/root/sequence/UUID, format, original body and
signed-envelope hashes, parent and writer key/epoch. A separate reference hash
checks the original bounded scratch record during comparison. Legacy physical
body references are excluded from cross-checkpoint signed-identity equality:
repagination may change physical roots while preserving exactly the same signed
envelope. `canonical_hash_bounded` computes plain BLAKE3 of the exact Postcard
encoding in one bounded pass without an encoded copy, including nested envelopes.
Legacy revision body hashing now also streams its unchanged derive-key encoding.
Existing signed layouts, domains, protocol vectors and hashes remain unchanged.

The transition streams ordered fixed rows and performs bounded indexed point
joins. It preserves every historical fence, retained original signed revision
and tombstone prefix. Dropped revisions require a covering tombstone; existing
floors cannot move backward or change at the same sequence. A new/advanced floor
must name a revision in the trusted predecessor, with exact original UUID/body
hash and this successor's generation. It cannot invent retired history or retire
a new candidate in the same checkpoint. Both cursors and all declared row counts
must reach exact EOF; missing or extra rows cannot quietly become an accepted
prefix. Original reference rows, keys and signatures are checked as they are read.

Only unchanged retained revisions can rely on removed owners or historical
writer keys. Every new revision requires an active member and an exact latest
nonrevoked writer returned from the same independently certified event snapshot.
The callback's result is compared to the signed writer fields and the proposed
latest fence. Lookups cache at most 256 active owners; no collection scales with
roots, history, fences or sources. A successor advances a fence by exactly one
and needs a new revision at that key; initial checkpoints can include certified
contiguous history before their first revision. New revisions cannot reuse UUIDs
in the predecessor's retained/last-retired ID index. The complete enclosing
retention/quota and any archival ID obligations remain separate policy gates.

Both full public inputs and conservative bounded row-comparison work share one
required trusted job budget. Paged input charges its full byte/page/record ledger
again for this job, including every logical closure occurrence. Legacy input
keeps its existing individually bounded 32 MiB certificate admission as one
legacy object; temporary indexed fields and every comparison/write are debited
by the separate row reservation. Four KiB per bounded row attempt and a fixed
local descriptor bound the comparison bytes; checked arithmetic and independent
record/page caps reject exhaustion before the large join or writer lookup.
The proposed public proof also retains its own original admission. No input
boundary resets either ledger and no peer-selected limit is trusted.

All comparison and temporary legacy indexing use the existing private scratch
transaction. Ignored writes, orphan namespaces, bad snapshots, invalid old
signatures and late row/tail errors return no transition/signing capability;
failed jobs discard their private store and rebuild. The completion marker binds
the current header, both trust snapshots and exact admitted work. Current event
and previous-state snapshots are reread at the end and again around later signing
or certificate binding. `CatalogQuorumPagedCheckpointIndex` now owns this
transition proof. The earlier raw public-body signing/binding methods have moved
to `CatalogCheckpointTransitionIndex`; no normal producer calls these draft APIs.
No production database writer spans traversal, comparison or callbacks.

Checkpoint trust validation now follows existing checkpoint/event roster rules,
which permit multiple certified peers in one failure domain. The earlier genesis
helper incorrectly required unique domains across the roster. Node IDs stay
strictly ordered/unique, recovery and Ed25519 keys remain validated, and domains
remain nonempty and at most 256 bytes. Per-coding-group distinct-domain placement
checks are unchanged. A core regression covers the legitimate cohosted roster.

Eight focused store fixtures pass, covering first publication, legacy formats
3–7, unchanged paged continuation, original signed identity, revoked/superseded
current writers, one-step rotation, exact monotone retirement, invented/new floors,
removed-owner retention versus new mutation, prior UUID reuse, both-input/scan
admission in all dimensions, changed snapshots and missing/orphan/ignored rows.
A 4,096-fence fixture spills beyond the 1 MiB cache, fails after a valid history
prefix or under a tightened real SQLite limit, then rebuilds and signs. This is
structural metadata evidence, not real retained 1 TiB payload qualification.

Validation: the full locked regression passes all 170 core and 227 ordinary
store tests (26 store tests ignored). Strict locked workspace/all-targets
Clippy and formatting/diff checks pass. The eight focused transition fixtures
also pass after the final Clippy simplification. No network/native,
release/platform or real retained 1 TiB runtime gate was rerun for this step.

These are public authority transition proofs. Original coding lifecycle and
fixed legacy-group migration, full retention/quota policy, private/bootstrap/
native and information/parity payload custody, complete durable ownership and
atomic certified-current publication/retirement guards remain required. The
normal producer/recovery/retained-capacity and platform/release gates stay open.

## Exact certified variable coding state before paged signing (2026-10-08)

`CatalogCheckpointCodingStateIndex` now binds a completed public proposal to one
independently certified current variable coding state before authority successor
comparison and draft signing. The former public-body-to-transition route has
moved to this private completed wrapper. A raw manifest, header or directory
proof cannot construct it. `CatalogCheckpointTransitionIndex` retains this
coding proof and exposes the original body/cursors through its existing accessor.
No normal checkpoint producer calls these draft APIs.

`CatalogCheckpointCodingTrust` contains the bounded independent checkpoint/event
snapshot and complete retained/retired variable-group counts. Counts are trusted
certified-history scalars, never copied from the proposed root. Every original
directory group is matched through a fixed `CatalogCertifiedCodingGroup` point
lookup: guild, original group ID and profile, plain BLAKE3 hash of the complete
original signed witness, add event, retirement event and retention deadline must
all agree. The required trusted reader must check original delegation,
historical membership/domains and bound add evidence, including legacy add
bindings, from the same certified snapshot. The convenience fact constructor
bounds the typed descriptor before legacy identity hashing and checks group
identity/shape; it is data, not a certificate or authority token.
Implementing the production bounded certified-history reader remains required;
this stage does not use the flat `DynamicGuildState` or clone its group history.
Point reads return already verified fixed indexed facts. History ingestion or
replay must be admitted separately by the enclosing job before this phase;
the callback cannot hide a catalog-sized replay inside a fixed point lookup.

Complete trusted counts and exact cursor EOF prevent a proposed subset from
dropping retained history. Unrelated and retired groups remain until certified
forgetting. Fixed placement rows record current eligibility without caching a
catalog-sized collection in memory. Every original packed-sector row and its
coverage point must resolve to an active group whose trusted authorization is
`CurrentPlacement`. Historical authority can preserve other retained groups,
but cannot cover current packed input. All groups and sectors must reach exact
declared counts; missing/extra rows cannot turn a valid prefix into completion.

The new join uses the same encrypted disposable store and one transaction. It
checks empty namespaces before writing, verifies every insert/readback, rereads
the independent snapshot and rechecks all earlier completion markers before
publishing its own marker. The marker binds the original header hash, exact
trusted snapshot/count hash and admitted work. Ignored writes, stale snapshots,
unavailable certified facts and late row/storage errors return no usable proof.
Signing/binding checks the new marker as well as authority, packing, directory
and authority-transition completion. The original signed layouts, group IDs,
transcript hashes, coding ranges and protocol vectors remain unchanged.

A required separate trusted job budget admits the entire public input and
conservative scan/point/writeback work before the first history lookup. Checked
accounting charges fixed data rows at 256 bytes, roster rows at 512 bytes and
fixed markers at 4 KiB, with independent record and page-occurrence caps. The
authority successor carries this admitted work forward before adding the prior
public input and authority comparison; it cannot reset the coding debt. The
existing proof retains its original public-input budget too. Internal bounded
row access preserves all geometry and canonical checks while completion is
checked around the scan. It avoids repeated large descriptor reads for millions
of group and coverage points; public cursor entry points retain their guards.
This is work admission, not the full retained dataset/guild or physical quota
policy, which remains open under R3-SINGLE-OWNER-METADATA.

Six new fixtures cover bounded typed descriptors, original witness/profile/
lifecycle substitutions, independent count/member/event mismatch, missing and
failed trusted history,
retired/unrelated retained groups, current versus historical coverage, all
budget dimensions, arithmetic bounds, stale/error final snapshots, orphan and
ignored writes, missing/extra original rows, late failure across 32 real coding
witnesses, actual SQLite page-limit exhaustion, rollback and fresh rebuilding.
The existing signing/completion and 4,096-fence spill fixtures now require this
proof too. This remains structural metadata evidence, not real retained 1 TiB
payload qualification. The existing authority format still requires retained
revisions; no empty-certificate semantics are introduced.

Validation: all 170 locked core library tests pass. The final locked store
library run, with four test threads, passes all 233 ordinary tests (26 ignored),
including the final typed-descriptor bound and coding-debt regression. Strict
locked workspace/all-targets Clippy and formatting/diff checks pass. No
network/native, release/platform or real retained 1 TiB runtime gate was rerun.

Fixed legacy-group migration, full original coding lifecycle transitions,
production certified-history indexing, private/bootstrap/native and information/
parity payload custody, complete durable ownership and atomic certified-current
publication/retirement guards remain required. Normal consumers, full retained
capacity/quota and release/platform gates stay open.

## Bounded disposable original guild-history reader (2026-10-08)

`CatalogGuildHistoryIndex` supplies a concrete bounded source for the draft
checkpoint's certified coding facts and writer history. It starts from an
independently trusted original `QuorumGuildGenesis`, verifies its original five
signatures and genesis identity, and streams every original event from sequence
one through exact EOF. A separately supplied compact `PagedCheckpointTrust`
binds the final guild/genesis, sequence/head, membership epoch, quorum, exact
active roster and expected previous checkpoint. This snapshot never comes from
the proposed body. It is reread around completion, including after marker
write/readback. Missing/gapped/extra events, changed tips or unavailable original
evidence reject the job; no valid prefix can manufacture the completion token.

`GuildAuthoritySnapshot` retains only the bounded roster and event tip. It reuses
existing membership/quorum/signature/placement rules on bounded temporary state,
without copying accumulated writer, recovery or coding vectors. Non-membership
events require a separate indexed transition validator. The store implementation
checks active subjects, strong keys, exact successive epochs, revocation,
original group identities and placement, retirement deadlines and certified
forgetting. Checked sequence/epoch arithmetic rejects overflow. Scoped original
event and legacy-binding decoders bound member/domain/signature/ciphertext
allocations before decoding nested payloads. Every original event variant
roundtrips unchanged, and streamed event hashing preserves the original domain
and positional bytes. The existing bounded original coding-witness decoder is
shared with the history reader; decoding alone grants no authority.

Memory stays bounded by a fixed number of roster snapshots and original
event/witness buffers. An encrypted disposable record store with its existing
1 MiB cache holds
membership epochs, full writer/recovery histories and retained variable groups.
Each original Add verifies the exact event-bound signed transcript, its original
plain BLAKE3 hash, full signature/RS replay, original descriptor equality and
historical attempt delegation/member/domain authority. Legacy Adds additionally
require the exact original-signers quorum binding. No witness, group identity or
binding is recreated from the proposed checkpoint. The ControlStore source uses
`guild-event`, `coding-event-transcript` and `coding-legacy-add-binding` through
bounded metadata and payload queries. A pre-binding store missing event-bound
evidence fails closed; automatic whole-state fallback is not introduced.

The completed final scan precomputes fixed coding facts of at most 256 bytes,
including original lifecycle/profile/witness hash and placement under the final
roster. Retired and unrelated groups remain until certified Forget; re-adding a
forgotten original group retains its original ID and exact new Add event/witness.
Point reads do not fetch a full descriptor or replay a witness. Historical writer
and recovery epochs remain addressable after revocation/removal. Current writer
lookup requires an active owner and the latest exact incarnation; revoking that
incarnation cannot fall back to an older unrevoked key. A private borrowed view
checks completion around enclosing scans, rather than rereading a marker at
every fixed point. No raw decoder/store accessor constructs a completed index.

One disposable transaction covers all replay rows and the completion marker.
Empty namespaces, exact canonical key/row checks, conditional writes and exact
readback catch orphan/ignored/missing writes; storage or late history errors
return no completed projection. Production SQL writers are not held during
traversal. Each input metadata reference is admitted before payload fetch;
original object and nested limits remain fixed. Checked byte/record/page work
preserves prior admitted work, charges original payloads and indexed replay
reads/writes/readbacks, and reserves fixed snapshot/marker work before deriving
the marker. `validate_certified_history_coding_state` carries the completed
history ledger into the public coding proof and its authority successor, without
resetting history admission. This work ledger does not replace aggregate physical
allocation or complete dataset/guild quota policy.

Four new core fixtures cover bounded projection replay, all original event
layouts/hashes, nested bounds, failed transitions, stale certificates, required
subject signatures, overflow and original legacy binding signers. Nine store
history fixtures cover actual original genesis/events/witnesses and ControlStore
metadata reads, valid signed but invalid transitions, invalid historical
membership despite valid witness replay, latest revocation/removal, complete
retire/forget/re-add identity, missing/changed witnesses and legacy binding gaps,
exact EOF/tip, all prior admission dimensions, ignored writes/orphans, a real
SQLite capacity failure across 512 certified writer rotations and fresh rebuild.
A tenth store fixture checks that history debt survives coding completion and
rejects each under-admitted dimension before group lookups. These are bounded
structural fixtures; they do not qualify a real retained 1 TiB dataset or a
history projection spilling beyond its 1 MiB cache.

Validation: the final locked core/store run passes all 174 core and 243 ordinary
store tests (26 ignored), with four test threads. The final added assertion for a
changed tip after marker write/readback also passes its focused run. Strict locked
workspace/all-targets Clippy and formatting/diff checks pass. No normal native,
network/topology, installed release/platform or real retained 1 TiB runtime gate
was rerun.

Normal producers/consumers still use the existing flat paths. Publishing and
maintaining a durable compact certified-current tip and incremental indexed
history, complete original coding successor comparisons, fixed legacy-group
migration, private/bootstrap/native and information/parity payload ownership,
atomic certified-current publication/retirement, complete aggregate quotas and
real retained 1 TiB/release/platform qualification remain required. This reader
does not activate a peer format or change any original signed identity.

## Original-history prefixes and paged coding successors (2026-10-08)

The disposable history projection now retains a fixed original tip for genesis
and every certified event, plus a fixed row for every variable coding Add
incarnation. The latter is keyed by original group ID and big-endian Add
sequence. Retirement and forgetting update the row through checked conditional
writes; forgetting removes the full retained descriptor but preserves its
original profile, signed witness hash and lifecycle. The final replay checks
every retained descriptor against its archive row and reaches exact archive
EOF/count. All new metadata, reads, writes and readbacks use the existing work
meter and disposable transaction. Ignored archive updates and capacity errors
cannot produce a completed projection.

`CatalogGuildHistorySnapshot` is a private-construction historical-prefix view.
Admission reserves the bounded event tip and 128 KiB epoch roster before reads.
The supplied historical trust must match the independently replayed original
guild/genesis, exact sequence/head, membership epoch, quorum and active roster.
Retained/retired counts come from the original prefix, never from the proposed
checkpoint. One indexed inclusive reverse range read resolves the most recent
Add at or before that prefix. SQL checks key/payload lengths before allocating
either blob. Canonical fixed-row checks apply; later retirement is clipped and
forgetting at/before the prefix returns absence. A later re-Add of the same
original group ID cannot replace the old prefix's witness. Historical writer
lookups exclude future activation and clip future revocation while preserving
authorized retained keys after owner removal. No witness replay, incarnation
scan or catalog-sized in-memory collection is hidden in a point lookup.

`validate_certified_history_authority_transition` uses this concrete projection
for current placement, both complete variable coding states, retained writer
history and latest current writer authority. It rechecks current fixed group
facts and placement, then requires the predecessor's exact original event head
and roster on the same certified chain. Paged predecessor directory counts and
every original group/profile/witness/lifecycle must match that prefix through
exact EOF. Every retained fence in both bodies must match the original writer
epoch/public key; later revocation does not rewrite authorized history. The
existing full original revision/tombstone/UUID successor comparison then runs.
A larger event sequence or membership epoch with a valid quorum cannot admit
a forked predecessor. The original quorum-bound paged predecessor remains
required, and no original signed envelope or group identity is regenerated.

Legacy certificates retain their original decoder, 32 MiB bound, hash and
quorum verification. An empty coding prefix can migrate through this route.
A legacy certificate containing fixed groups, or omitting variable groups
retained at its original prefix, fails closed pending explicit migration. This
does not reinterpret fixed groups or silently discard historical authority.

The complete replay/prior-work ledger carries into the comparison once. A
coding proof which already admitted that history does not pay the same replay
again; a fixed-fact proof admits it here. Checked reservations admit both full
public inputs and all extra historical point/scan work in bytes, records and
page occurrences before the history joins. The existing scratch transaction
covers temporary legacy indexing, successor checks and the completion marker.
Late unavailable history, stale independent trust or missing rows yields no
usable successor. The private marker records whether concrete original-history
validation completed, exposed by `has_certified_history_transition`. The
external-authorizer draft route still exists; normal publication must require
the concrete history checks when integrated.

Three prefix fixtures compare every original state with the bounded historical
view, including writer activation/revocation, retire/forget/re-Add, changed
placement, admission, malformed/oversized/missing rows and ignored updates.
Four end-to-end fixtures start from actual five-member genesis, certified
membership/writer events, original source-owner signatures, an original bound
version-three coding witness and eleven-member quorum certificates. They cover
initial signing, a paged successor with a different signed witness after
Forget/re-Add of the same group ID, retained writer-key substitution, exact
work carry/no-double-charge, under-admission in every dimension, missing old
incarnations and fresh rebuilding, changed final trust, a later valid quorum
fork and empty legacy migration versus omitted variable history. These fixtures
build new packing descriptors with supported version-two whole-byte-root
semantics from actual packed bytes before creating any coding group/certificate;
they preserve all subsequently certified IDs, original witnesses and revisions.
No production packing layout, signed codec or protocol vector changes.

Validation: the full locked Store library run passes all 250 ordinary tests
(26 ignored), with four test threads. Strict locked workspace/all-targets Clippy
and formatting/diff checks pass. The final focused archive/range regression
also passes. Core production code is unchanged in this step;
its previous 174-test passing run remains the recorded core evidence. These
remain structural metadata fixtures, not retained 1 TiB payload or
history-index spill qualification. Normal durable compact-tip publication and
incremental history maintenance, archive retention/compaction under complete
quota policy, fixed legacy migration, private/bootstrap/native and information/
parity payload custody, atomic certified-current ownership/publication/retirement
and all retained-capacity, native/platform/release gates remain open.

## Durable compact event authority for ordinary Node readers (2026-10-08)

Normal Node membership consumers no longer need to decode accumulated writer,
recovery and coding vectors after a durable compact authority projection exists.
`guild-authority-tip-v1` stores only the original genesis hash, bounded
`GuildAuthoritySnapshot` and a local checksum, capped at 128 KiB plus 128 bytes.
The snapshot includes removed members for historical authorization, event
sequence/head, membership epoch and quorum. This is private local state derived
from original accepted authority, not a new signed certificate, protocol format
or a substitute for the complete indexed coding-history proof.

Verified genesis installation, ordinary recovery, full dynamic recovery and
new event ingestion publish the projection in the same writer transaction as
their accepted original records, inherited legacy dynamic state, verifier/binding
evidence and pending-record cleanup. Original quorum/non-membership validation
and witness replay run in the existing ingestion paths before publication. A
private publisher checks the expected compact predecessor and original event
tail under the writer, checks every accepted write/readback and deletion, then
publishes the exact new projection with CAS/insert/readback checks. Ignored,
corrupted or late failing writes roll back both authority and accepted records.
Original record IDs, signed bodies, hashes and serialized enum identities remain
unchanged. The transaction still includes the inherited flat state; replacing
that growing legacy write with indexed mutations remains required.

Active and historical member authorization, coordinator lookup, guild summary
membership and NodeReader peer-exchange rosters consume fixed projection reads.
SQL bounds the payload before allocation. Canonical/schema/roster/checksum
validation, original installed-genesis binding and an exact bounded original
event-tip lookup reject missing, conflicting, stale and oversized rows. A final
projection reread rejects concurrent authority changes. Lookup performs no full
history traversal or witness replay. Genesis reads in these paths also have a
fixed SQL payload bound. A checksum detects local corruption; it does not make
arbitrary proposed membership authoritative.

An older store with no projection retains its existing full legacy validation
path. The next verified genesis/recovery/event installation fills the projection
atomically. A present malformed or stale projection never silently falls back to
another authority. Automatic original-history rebuilding for legacy/downgrade
stores remains required; this step does not certify that migration gate or
remove the inherited whole-state paths elsewhere.

Validation covers all 423 ordinary locked Node library tests (21 ignored).
The full run passed 420, with two legacy-export fixtures failing because their
directly injected history left a genesis projection stale. After those fixtures
explicitly model older stores without the projection, the final seven-target
run passes both export cases and all five projection fixtures, including the
added initial-publication rollback and original-genesis signature assertions.
Production code is identical across these runs. Strict locked workspace/
all-targets Clippy and formatting/diff checks pass.
The focused fixtures exercise actual original genesis and signed membership/
writer events, coordinator removal, active versus historical members, reopen,
missing legacy projections, fixed bounds/checksum/genesis/tip failures and stale
proposals. They replace the unused flat blob with an unreadable 2 MiB record to
prove ordinary projected readers do not decode it. SQL triggers exercise ignored
and corrupted writes in the original event/state/projection batch, pending-record
deletion and initial recovered-guild publication, followed by valid retry.
The existing legacy-export peer fixtures explicitly model older stores without
this projection when directly installing legacy history. Their corrupt-signature,
parent, Add, epoch and unavailable-evidence cases continue to exercise original
history validation, rather than failing early on a stale fixture projection.
This does not qualify a retained 1 TiB dataset, indexed coding-history spill,
full quota policy, private/payload ownership, normal paged checkpoint production
or the remaining native/platform/release gates.

## Durable bounded membership epochs for coding authority (2026-10-08)

Normal coding-attempt authority checks now use bounded current and historical
membership projections. `guild-authority-membership-v1` stores one immutable
bounded roster per indexed membership epoch, including removed members, quorum,
the original genesis hash and its original event tip. Each row also binds the
exact original certificate bytes, including signatures, with a local checksum.
Rows have a 128 KiB plus 128 byte SQL payload limit; the completion marker in
`guild-authority-membership-tip-v1` has a 256 byte limit. These are private local
projections of already verified original authority, with no signed-layout,
record-identity or wire-version changes.

The existing verified genesis/recovery/event publisher prepares at most one new
epoch row outside the production writer and publishes it with the exact original
accepted records, inherited flat state, compact tip and pending-record cleanup
in one transaction. Non-membership events preserve the existing epoch row and
only advance the fixed marker. Expected marker/row checks, checked insertion,
CAS and exact readbacks reject ignored, corrupted and cross-record SQL writes;
final checks after compact publication include the existing and new epoch rows.
Accepted original-record readbacks and final genesis/tip checks also run after
all projection writes; final deletion checks reject recreated pending records.
This closes a late-write ordering gap without adding another whole-state
readback: the existing accepted-record checks move to the end of publication.
Idempotent ingestion preserves an existing epoch's original tip. This bounds the
additional index mutation; the inherited full dynamic-state mutation still
needs replacement by complete indexed history maintenance.

Fresh guilds index from epoch one. Older or fully recovered states without the
index seed an explicitly marked contiguous suffix at their current epoch; they
do not manufacture old epoch rows from a later roster. Requests below this
suffix retain the existing original-history replay path. Missing or malformed
rows inside the completed suffix, stale markers or changed original certificate
bytes fail closed without legacy fallback. Lookup checks the installed original
genesis, current compact authority/tail, requested epoch identity and original
certificate, then rereads the marker, compact tip and epoch row. Normal indexed
reads do not traverse the full event chain, materialize writer/recovery/coding
vectors or populate the inherited full-state historical cache. Historical
lookup reuses the genesis/certificate already checked for that lookup, and
preparation reuses the accepted genesis snapshot; neither decodes and verifies
the same original genesis again merely to compare the epoch-one row.

Current attempt checks use the compact roster and retain the original signed
plan validation, root-binding frame budget, membership/placement rules and
deadline. Historical replay/cleanup uses the requested indexed epoch and
retains its original placement/domain authority even after removal or relabeling;
it remains independent of the current attempt deadline, as before.

Five new fixtures exercise real original genesis and signed writer, Add/Remove/
Relabel/SetQuorum events, signed coding plans, current versus historical fencing,
expired cleanup, invalid signatures/domains, reopen and an unreadable unused
2 MiB flat state. Faults cover ignored/corrupted epoch/marker writes, compact or
marker triggers corrupting other epoch rows, original events or flat state,
recreated pending records, initial publication rollback and
valid retry. Negative lookups cover bounded SQL payloads, missing/wrong epochs,
checksums, changed historical certificate signatures and missing originals.
Legacy suffix fixtures verify original replay below the indexed range and
refusal to fall back for missing rows inside it. The older export-peer fixtures
explicitly omit both local projection markers when directly injecting legacy
history, keeping their original evidence-validation cases meaningful.

Validation: the full locked Node library run with four threads passed 427
ordinary tests (21 ignored). Its only failure was a successful survivor export
exceeding the fixture's unchanged ten-second assertion for bypassing an unused
unavailable peer. After the final publication-check ordering and genesis-work
reuse changes, the serial eleven-target rerun passes all ten authority fixtures
and the complete survivor-export fixture. A four-thread fourteen-target rerun
also passes all ten authority fixtures and all four legacy-export peer fixtures,
including the original timing assertion. All 428 ordinary Node tests are covered
across the broad and final targeted runs; this is not a claim that a single full
run passed under the final tree. The original topology/release gates remain open.
Strict locked workspace/all-targets Clippy and formatting/diff checks pass.

Bounded legacy-prefix/downgrade rebuilding, durable writer/recovery/group
indexes, flat mutation replacement, archive retention and complete quota policy,
private/bootstrap/native and information/parity payload custody, atomic
certified-current publication/retirement, retained 1 TiB qualification and all
remaining native/platform/release gates remain open.

## Incremental durable original guild history and bounded group readers (2026-10-08)

`CatalogDurableGuildHistory` persists the shared original-history validator's
point rows in the encrypted production control store. Eight private
`guild-original-*` namespaces contain historical membership rosters, writer and
recovery epochs/latest pointers, retained groups, every original prefix tip and
all coding incarnations. Each bounded row has a fixed 64 byte header binding
its original genesis and a checksum over its original row kind, key and canonical
payload. The bounded `guild-original-tip-v1` marker contains the exact verified
original-prefix authority, lifecycle counts and cumulative represented work.
These are local projections created by checked publication, not new peer
certificates or authenticated substitutes for missing original evidence.
Their descriptor duplication, prefix/incarnation rows, scratch reservations
and retained original evidence must enter the complete metadata and physical
quota policy; bounded point access does not establish a retained-capacity fit.

Preparation verifies independently signed original genesis, or advances exactly
one original certificate from the existing verified prefix. It uses the existing
`advance_indexed` and full original-history effect validator: original quorum
and subject signatures, membership/quorum transitions, exact writer/recovery
rotation and revocation, group placement, original Add-bound transcript hash or
mandatory legacy quorum binding, bounded transcript replay, historical attempt
membership, retirement deadlines, forgetting and same-ID re-addition all retain
their existing rules. It copies only the event's selected point rows into a
bounded encrypted disposable SQL overlay, with a 1 MiB page cache and a roughly
2 MiB database ceiling. Linux scratch admission uses the control store's mount
and reserves its checkpoint/WAL exposure. No original proof, witness replay or
scratch filesystem operation holds the production SQL writer.

The private prepared mutation guards the old marker and each selected original
point row, applies checked insert/CAS/delete operations, then verifies the exact
published marker and rows. The normal Node publisher joins it to the transaction
containing accepted original records, the inherited flat state, compact
current authority, historical membership rows and pending cleanup. Final
original-record, deletion and projection readbacks occur after all mutations,
including the compact-tip write. Preparation conservatively reserves marker
encoding/guard/write/readbacks, repeated namespace admission, selected input
guards, durable writes and both publication readbacks in its per-event ledger.
An unchanged verified-prefix guard rereads its marker without rewriting it or
adding old evidence again to the cumulative original-history ledger.

New guilds index from original genesis and advance with normal ingestion. Older
or recovered histories without this index start at independently verified
original genesis; a later roster never fabricates earlier key/group rows.
Peer reconciliation follows legacy-Add rebinding with at most sixteen local
steps, ending the batch when a completed step exhausts its 25 ms cooperative
allowance. Each step rereads one bounded original event and its required original
evidence, validates outside the writer, then guards the current compact tip and
original event bytes while publishing. Missing original Add witnesses or legacy
bindings stop the prefix without advancing it or substituting a group-key
witness. This is a bounded catch-up facility, not a qualification of migration
throughput or complete upgrade/downgrade behavior. Older stores missing the
compact current-tip projection still need its automatic rebuild path.

Normal Node/reader variable-shard serving, the emergency reader's group lookup
and the group lookup in variable repair use bounded retained-group point reads
when this original index reaches the current independent compact authority.
They check the original genesis and current original tail, exact indexed scope,
row identity/checksum/lifecycle and final row/marker/authority stability. The
lookup reuses the already checked compact record and compares original genesis
bytes at the end, avoiding redundant genesis signature replay for the same
lookup. Existing holder assignments, payload Merkle roots and live-checkpoint
checks remain. A current missing or damaged indexed group fails closed even
when the flat state contains a valid-looking copy. An explicitly incomplete
original prefix retains the compatibility flat-state reader until catch-up;
this remaining compatibility allocation is not a bounded-history claim.

Five new Store fixtures cover both original bound and legacy Adds, every
original event variant, rotation/revocation, retire/forget/re-add, reopen after
each event, exact correspondence with original full-state effects, cumulative
and exact step budgets, missing original witnesses/bindings, invalid signatures
before witness I/O, stale prepared prefixes/point rows, bounded corrupt row
reads and ignored/corrupt/cross-record SQL writes. Publication faults include
ignored group updates/deletions and a late marker trigger recreating a deleted
group, with rollback and valid retry. Four new Node fixtures cover actual
signed witnesses and physical parity, reopen, serving through both Node and
reader with an unreadable unused 2 MiB flat state, wrong guild/holder, truthful
legacy-prefix catch-up with missing original Add evidence, refusal to fall back
for corrupt/missing current rows, and original-record/authority/pending-cleanup
rollback and retry under SQL faults.
Legacy checkpoint-only peer fixtures explicitly omit all local authority/history
projections when directly injecting synthetic full state without an original
event log. A verified genesis projection beside that synthetic later tail is
not a valid model of an older store; the rootless-replacement audit correctly
rejects a group missing from that projected history. The fixture adjustment
preserves its checks that physically available wrong-byte/rootless groups cannot
authenticate a retained revision, along with the separate completed-index
corruption tests that forbid compatibility fallback.

Validation: the broad locked Store library run passes 254 ordinary tests
(26 ignored). After final publication-accounting/deletion-guard changes and
the distinct-witness re-add assertion, all five original durable-history
fixtures pass on the final tree. All 255 ordinary Store tests are covered
across those runs. The broad locked Node library run with four threads passes
431 ordinary tests (21 ignored); its only failure is the legacy rootless audit
fixture retaining a genesis projection beside synthetic later state. Direct
reproduction confirms that failure. After the explicit legacy-fixture correction,
the final four-thread eighteen-target run passes all fourteen authority
fixtures and all four peer fixtures using the corrected helper, including the
rootless audit, packed restore/cold recovery, parity-only cold recovery and
ready-local recovery quorum checks. All 432 ordinary Node tests are covered
across broad and final targeted runs. These are combined validation results,
not a claim that a single full run passed under the final tree. The survivor
export's unchanged timing assertion passes in the broad Node run. Intentionally
ignored provisioned/native/topology cases are not qualified by these runs.
Strict locked workspace/all-targets Clippy and formatting/diff checks pass.

Complete flat-state mutation replacement, normal writer/recovery-reader
integration, automatic old-store compact-tip rebuilding, migration throughput,
archive retention/compaction, complete metadata/quota admission, certified-current
checkpoint publication/retirement, private/bootstrap/native and information/
parity payload custody, retained 1 TiB qualification and all remaining native/
platform/release gates remain required. Signed record layouts, hashes and wire
versions are unchanged; normal paged checkpoint producers remain disabled.

## Frozen bounded key authority for normal consumers (2026-10-08)

Normal recovery-key and retained-writer consumers now use a frozen authority
reader over the completed durable original-history index. A successful batch
checks the original installed genesis, compact current authority and exact
original tail, uses bounded indexed point reads, then checks the same genesis
bytes, compact record/tail and history marker before returning. It reuses that
checked genesis across the member key lookups.
Group serving uses the same reader and retains its exact original identity,
lifecycle and holder/payload checks. No signed layout, record identity, wire
version or durable index schema changes.

A missing/incomplete original index explicitly uses the existing compatibility
state. That state is decoded/validated once per batch, checked against the
independent current roster/tip, and fenced by its exact length and content hash.
The final SQL read is bounded by that observed length. Appearance of a compact
projection during a legacy-only lookup, changed original genesis/tip/completion,
changed legacy state or a mismatched current index fails the batch. Current
indexed readers do not load the legacy blob. This keeps legacy rebuilding debt
explicit and prevents a changed compatibility source from yielding a successful
mixed-scope result.

The Store view adds bounded latest/current recovery lookups. The latest pointer
must name a positive epoch no later than the represented original event tip and
an existing valid envelope row. A missing pointer beside epoch one is damaged
completed state. The greatest registered epoch is usable only while unrevoked;
an older still-unrevoked epoch never replaces a revoked greatest epoch. Removed
subjects' envelopes remain addressable, matching the original full-state rule;
callers enforce their active-member or historical-recovery scope. Retained writer
lookup returns the exact original epoch's public key, including after revocation
or removal. A missing writer epoch inside the registered contiguous range fails
closed. No current malformed/missing key row triggers flat-state fallback.

Backup submission uses bounded current membership/coordinator authority; backup
claim checks current recovery envelopes for the bounded active roster before
claiming a job. DHT recovery publication gathers active members/envelopes in one
frozen batch and local bundle validation compares the exact current envelope.
Supplied recovered remote history retains its original full validation path.
Idle recovery-key reconciliation now returns before materializing full history
when registration is unnecessary; existing writer fences similarly use exact
indexed historical keys before taking the registration path. Actual new/locked
registration still uses the original event validation, signatures and mutation
path. Signature-lock reads are bounded by the existing original-event limit
plus 256 bytes of lock overhead. Endpoint refresh, removed-holder endpoints,
recovery-sequence probes, readiness publisher selection, local recovery-resume
binding and legacy packing-attestation membership use the bounded current roster.

Two new Store fixtures exercise latest revocation without older fallback,
subsequent rotation, removed-subject semantics, unregistered subjects and missing,
corrupt or oversized latest/envelope rows. Four new Node fixtures cover retained
revoked/removed writers, recovery revocation/rotation, completed-row failures
without fallback, batch fences for genesis/current/history/legacy changes,
coordinator backup admission/claim with unreadable unused 2 MiB flat state,
caller rejection, idle registration and oversized signature locks. The existing
DHT rotation/revocation fixture now creates real sealed publications and validates
all four dynamic checkpoint formats while the unused flat state is unreadable;
it also exercises bounded endpoint/probe/readiness/recovery-resume consumers.

Validation: the locked full Store library suite passed 257 tests with 26
ignored, and the locked full Node library suite passed 436 tests with 21
ignored. The focused Node authority/backup/DHT selection also passed all 20
tests. Both full suites completed before a syntax-only Clippy let-chain
cleanup. Final-tree focused runs passed all seven Store durable-history and
all 20 Node authority/backup/DHT tests. Ignored provisioned/native/topology
cases remain unqualified. Strict locked workspace/all-targets Clippy and
formatting/diff checks pass.

Actual event mutation and key-registration actions, unbounded job queue scans,
remote recovered-history materialization, complete checkpoint body/authority
joins and ownership/publication, migration throughput, archive retention and
full metadata/physical quota policy remain required. These authority reads do
not qualify a retained 1 TiB dataset or the remaining native/platform/topology/
release gates. Normal paged checkpoint producers remain disabled.

## Original full-state current-writer revocation rule (2026-10-08)

Review of the normal key consumers found that the original
`DynamicGuildState::writer_epoch_is_current` filtered revoked keys before
selecting the greatest epoch. With unrevoked epoch one and revoked epoch two,
it incorrectly made epoch one current again. The paged original-history reader
and protocol already require no fallback. The helper now selects the greatest
registered epoch first and tests that exact epoch's revocation afterward.

Two new regressions first failed against the old helper. The Core fixture
replays original signed rotations/revocation, observes no current older writer,
preserves both exact historical public keys and permits a later valid rotation.
The Node fixture reaches the actual fresh-checkpoint coverage gate with an
original genesis, signed key events and a signed checkpoint. The old gate
accepted the superseded revision after revoking the latest key. The fixture
also checks original historical checkpoint coverage and unchanged retained-head/
successor validation after reopening the store. Historical key lookup, signed
layouts, certificate identities and wire versions are unchanged.

Validation: both new cases reproduced the old bug before the helper change
(one failing Core case and one failing Node case). After the fix, the locked
full Core library suite passed all 175 tests. A locked Node selection passed
all 24 cases: both normal key consumers and their authority fixtures, the new
fresh/retained checkpoint regression, resumable authority-epoch catch-up and
legacy checkpoint membership/quorum transitions. A locked Store selection
passed all eight durable-history/current-writer cases. The preceding full
Node/Store runs recorded above qualify the bounded-reader change; this
subsequent two-line helper correction is qualified by the full Core and
targeted Node/Store runs, not a repeated full Node/Store run. Ignored platform/
provisioned/topology cases remain unqualified. Strict locked workspace/
all-targets Clippy and formatting/diff checks pass.

This is a correction to the existing original checkpoint gate. It does not
replace its full-state history materialization or complete paged checkpoint
ownership/publication, full quota admission, retained 1 TiB or native/platform/
topology/release qualification. Normal paged checkpoint producers remain
disabled.

## Guarded enclosing public checkpoint ownership (2026-10-08)

`CatalogPagedCheckpointRetention` gives a concrete original-history-proven,
quorum-bound paged candidate one public metadata owner. It binds the exact
header, original certificate hash, independent trust hash, completed proof debt
and enclosing budget. External-authorizer-only draft transitions cannot enter.
The budget admits completed original/previous-proof work plus local public EOF
replay before ownership starts. The authority root, both packing roots and coding
directory acquire atomically. Bounded traversal pins every logical legacy
envelope, paged revision source tree and coding forest part before reading it;
complete original signed envelopes, source/bootstrap EOF, authenticated compact
packing source resolution and original coding witnesses must all replay locally.

The exact bounded original quorum certificate is stored in the same initial
transaction, with exact readback. Retry/reopen require the original descriptor
and certificate; missing, corrupt, substituted or oversized live evidence fails.
Published retries repeat typed EOF and check every exact dependency/pin instead
of accepting the journal state alone. Final publication rereads the exact local
certificate around its guarded state change.
The final cancelled root release removes the owner's certificate copy in the
same transaction as the pin and counter changes. The cancelled descriptor remains to prevent ID
reuse. Interrupted Building jobs replay their typed EOF with idempotent pins;
failed workers cancel only an unpublished job. Independent successor owners
preserve shared root closures across old-owner retirement.

Every initial/nested acquisition and final publication checks independently
certified event trust and the actual SQL checkpoint predecessor inside its short
writer, with a second check after mutation. Node's metadata entry point supplies
a frozen original-history reader over the compact accepted scope and exact
original genesis/tail/index marker. A complete index needs no accumulated flat
history. The fixed current-head query excludes certificate/body bytes and uses
SQL length selection before exposing the 32-byte hash. Independent original
authority and actual predecessor changes cannot publish a mixed-scope result.

Cancellation and every bounded root release check the actual current checkpoint
before and after mutation. A current owner cannot retire, including after reopen
or if the current head appears after cancellation. SQL-trigger mutations of the
head during cancellation/release roll back pins, counters, journal state and the
head change together. Future full activation must itself require a complete live
owner atomically; the metadata owner supplies no activation capability and does
not write the normal current checkpoint. Historical checkpoint/ancestor archive
ownership and its retirement policy remain required separately; removing this
owner's certificate copy does not retire the accepted protocol archive.

Store fixtures use original genesis, real signed event/writer/coding history,
concrete transition proofs and original quorum certificates. They exercise all
transitive public roots after capture retirement and reopen, a real certified
shared successor, interrupted Building replay, permanently cancelled IDs,
external-only proofs, stale trust, missing local EOF, ignored initial writes,
final event/base changes and atomic cancellation/root/certificate retirement.
Current-head fixtures include a 2 MiB body and invalid, zero, undersized and
oversized identity columns. Node fixtures construct a real signed legacy revision
at its original 64 KiB geometry, authenticated packed sources, original bound
coding Adds/witnesses and a complete original-history-proven quorum candidate.
The real Node entry retains it with unreadable unused 2 MiB flat state, retires
capture pins, reopens and preserves the metadata owner; changed original genesis
and a later accepted event reject the stale candidate.

Final focused validation passed all eight Store ownership/head-identity tests
and all 26 selected Node cases: the two new metadata-entry fixtures plus the
existing authority, backup/DHT, writer-revocation and legacy checkpoint/catch-up
regressions. The locked full Store library suite subsequently passed all 265
ordinary tests with 26 ignored against the same final functional tree. Strict
locked workspace/all-targets Clippy and formatting/diff checks pass. Node
validation here is the 26-case focused run, not a repeated full Node suite.
These are local public metadata and current-state guard tests;
ignored provisioned/native/topology cases remain unqualified.

This completes guarded public candidate metadata ownership, not the complete
enclosing protected checkpoint. Private metadata, native anchors, bootstrap
ciphertext and information/parity payload custody, all logical/history owners,
certified-current activation/retirement and cooperative worker integration, full physical/dataset/guild
quota and admission policy, archive retention, actual retained 1 TiB and native/
platform/topology/release qualification remain required. Normal paged checkpoint
producers remain disabled; original signed layouts and wire versions are unchanged.

## Checkpoint dependencies on published private revision custody (2026-10-08)

A public paged checkpoint owner can now retain an exact revision's existing
published private catalog. This adds an enclosing dependency to the actual
bundle, rather than constructing an independent copy of its roots or bootstrap.
The bundle's existing ownership preserves private native/Git pages, the signed
source root, bootstrap ciphertext, private page-source bindings and any existing
native/data-source anchor pins. All checkpoint dependencies must retire before
bundle cancellation can fence its sources or remove its bootstrap. A cancelled
checkpoint retains its dependency until that bounded cleanup step commits.

Acquisition requires the same concrete original-history-proven quorum candidate
and exact public owner descriptor/certificate. A bounded point lookup in the
completed authority join reads the original revision reference and its indexed
identity; a validly signed replacement reference under the same key is rejected.
The private bundle must contain that exact signed envelope. Node additionally
opens the owner-encrypted descriptor, checks ownership/scope and matches every
private root to the bundle. Independently frozen original event trust and the
actual SQL predecessor are checked inside the dependency writer before and after
mutation. A raw manifest, external-only draft history bridge, stale candidate,
missing private catalog or cancelled public owner cannot acquire a dependency.

Paired forward/reverse records bind the exact bounded bundle hash and private
work. Both pins and a cumulative work counter publish atomically with exact
readback. Private root logical bytes/pages, bootstrap ciphertext and conservative
bounded dependency/counter rows consume the remaining enclosing proof budget;
original history/proof and public replay debt are not reset. The count cannot
exceed the candidate's retained revisions. This is logical ownership admission,
not complete physical/dataset/guild quota or verified availability of every
source. Existing authenticated data-source replacement remains available and
atomically transfers physical anchor counts without changing the immutable
private bundle or checkpoint dependency.

The existing enclosing cleanup entry point releases at most one private revision
dependency or public root per call. Private dependencies retire before public
roots, retaining the original certificate until all have been removed. Each
paired delete/counter update is atomic and checks the actual current checkpoint
before and after mutation, including after cancellation and reopen. Shared
checkpoint owners keep the bundle live independently. One-sided, corrupt or
oversized dependency/counter rows, ignored SQL mutations and head changes inside
the writer fail closed and preserve custody. Cancelled owner IDs remain fenced.

Five Store fixtures construct real encrypted private catalogs, complete source/
packing/directory joins, original bound coding events and concrete quorum
history transitions. They exercise sharing and reopen after capture retirement,
bootstrap/private-page survival, existing native-anchor replacement/cleanup,
stale authority, validly signed reference substitution, oversized rows, rejected
private authentication, every paired pin/delete/counter fault, current-head
changes before and during retirement, exhaustion after public/proof work, and
cumulative admission/one-dependency retirement across two retained revisions.
The Store-only native recipes are explicitly opaque test records: they exercise
real durable anchor counts, not physical-file availability qualification.
The Node fixture builds and publishes a real owner-encrypted private catalog and
paged successor, then uses both real enclosing entry points with unreadable
unused flat state, retires public capture pins, reopens, reauthenticates private
roots, rejects another owner's key and a legacy reference, and retires custody
before the final public certificate. Existing original-authority/backup/DHT/
writer/catch-up cases remain part of focused validation.

The locked full Store library suite passed all 269 then-existing ordinary tests
with 26 ignored. After test-only shorthand cleanup and the fifth cumulative
budget regression, all five ownership fixtures passed on the final tree. The
27 selected Node original-authority/backup/DHT/writer/catch-up cases passed,
including the new encrypted-private-catalog fixture; a repeated full Node suite
was not run for this additive entry point. Strict locked workspace/all-targets
Clippy and formatting/diff checks pass. These are local ownership tests; ignored
provisioned/native/topology cases remain unqualified.

This preserves existing local private/native/bootstrap custody; it does not
complete all private/source EOF and information/parity availability proofs,
transitive history/ancestor archive ownership, certified-current activation and
retirement policy, cooperative workers/normal producers, physical/dataset/guild
quota or actual retained 1 TiB/native/platform/topology/release qualification.
Normal paged checkpoint producers remain disabled. Original signed layouts,
identities and wire versions are unchanged.

## Checkpoint custody of actual local information/parity roles (2026-10-08)

`retain_catalog_paged_checkpoint_payload_checked` binds an individual physical
variable-profile role to the same original-history-proven paged candidate owner.
An authenticated group point replay comes from the completed directory index,
including its original signed witness. It resolves information to its sector ID
and parity to its group ID, with the exact role index, assigned holder, guild,
Merkle commitment and original transcript hash. Virtual-zero roles have no
physical custody dependency. The concrete quorum/history proof, independently
read event trust, actual SQL predecessor, published owner and exact stored
certificate are checked around the dependency writer.

Node's `retain_paged_checkpoint_local_payload` checks the assigned local holder
and loads actual READY bytes through the active online volume locator. The
locator allocation is bounded to 512 bytes inside SQL. It checks the guild and
original commitment and recomputes the full Merkle commitment. Missing, STAGED,
unavailable or damaged bytes and malformed/oversized locators cannot publish a
pin. A signed witness or upload record alone does not establish possession.

Acquisition holds the control database's immediate writer across the physical
READY check and paired pin publication. Actual garbage deletion and bulk attempt
rollback hold that same writer across pin checks and their volume transaction.
This serializes acquisition and deletion across separate control/volume
databases. The callback view exposes pin reads and a narrowly scoped exact
volume-receipt retirement; it cannot change other custody state. Callbacks must
not start another control transaction. Pins preserve both READY bytes and their
active locators after Forget and attempt rollback. Repair keeps a custodied
source locator until verified replacement activation publishes its destination;
empty-volume retirement cannot erase a still-required locator. Existing verified
evacuation transfers the bytes and original activation evidence before source
withdrawal, without needing to release checkpoint custody.

Forward dependencies use the candidate owner plus coding group/role; reverse
dependencies use the physical storage ID/role plus owner/group. Thus independent
owners and different coding groups can share information without collapsing
their ownership. Canonical bounded paired records and a cumulative count/work
counter are published atomically, survive reopen and remain pinned after
cancellation until their individual cleanup step commits. The count is bounded
by the certified role summary. Exact retry adds no debt. Cleanup releases at most
one payload dependency before private revision dependencies and public roots,
checks the actual current checkpoint before and after mutation, and keeps the
original certificate until the final public root retires. Cancelled IDs remain
fenced. Orphaned, mismatched or oversized pin/counter records prevent deletion.

Admission adds actual payload bytes, bounded local dependency records and the
measured additional coding-point replay to original proof debt, public EOF replay
and private root/bootstrap work. The point reader reports actual encoded page
bytes, page occurrences and framed witness records; it does not substitute a
guessed per-group byte limit. Public, private and payload acquisition share one
remaining budget in either order. This logical work bound does not replace
physical, per-dataset or guild-wide storage accounting.

Four Store custody fixtures use real original coding/history/quorum proofs and
actual READY codewords. They cover sharing and reopen, exact retry, attempt
rollback, writer exclusion against a second connection, acquisition after
deletion, bounded retirement, stale independent trust, current-head changes
inside acquisition/release writers, ignored paired insert/delete/counter writes,
damaged records that must preserve physical bytes, and combined private/payload
budget exhaustion in both acquisition orders. Their Store-only receipt strings
are explicitly opaque; the Node fixtures use normal uploads and original signed
plans/witnesses for actual assigned information and parity holders.

Both Node fixtures reject missing/STAGED bytes and an oversized active locator,
use the frozen original index with unreadable unused flat state, retire capture
pins, install real signed Retire/Forget events, roll back the coding attempt and
reopen. They interrupt evacuation exactly after destination READY, retry rollback
with both copies present, then reopen and finish the verified move. They also
exercise local volume repair while the custodied source disk is unavailable:
the old locator survives staging, activation publishes a verified replacement,
and restoring the old disk leaves both copies protected until final owner
retirement. Shared owners retire independently before actual collection. These
tests exercise storage custody mechanics, not normal paged checkpoint production
or end-to-end historical repair/recovery policy.

The real information evacuation fixture exposed a previously untested normal
activation defect: uploaded information became READY with an empty receipt
field, whereas recovery stores its original verified transcript hash as local
activation evidence. Normal activation now stores that same verified hash
before READY. Migration retains its strict missing-evidence rejection and copies
the original evidence exactly. This corrects fresh uploads, without silently
rewriting old READY objects. R4 is reopened for an authenticated upgrade/backfill
and qualification of those historical uploaded objects; missing original
witnesses must remain an explicit failure, not fabricated evidence.

The locked full Core library suite passes all 175 tests. The locked full Store
suite passes 274 ordinary tests with 26 ignored; after the additional destructive
fault assertions and lint-only conditional cleanup, all nine private/payload
custody fixtures pass on the final Store tree. The locked full Node library
suite passes all 442 ordinary tests with 21 ignored, including both complete
information/parity custody lifecycles and the existing GC, rollback, migration,
activation, backup and network regressions. Strict locked workspace/all-targets
Clippy and formatting/diff checks pass. After lint-only wrapper cleanup, both
Node custody fixtures pass again on the final tree. Ignored provisioned/native/topology
cases are not counted as qualification.

This establishes custody of individual existing local roles. Complete
distributed availability and all private/source EOFs, transitive history and
ancestor certificate ownership, atomic certified-current activation/retirement,
cooperative normal producers, full physical/dataset/guild quota and actual
retained 1 TiB/native/platform/topology/release qualification remain open. Normal
paged checkpoint producers remain disabled. Original signed identities and wire
layouts are unchanged.

## Authenticated upgrade of historical information activation (2026-10-08)

Prior normal information uploads can be physically READY with the original
attempt and verified transcript hash but an empty activation-receipt field.
Normal evacuation now upgrades that specific legacy state using its original
signed witness. It does not relax the ordinary READY transfer/copy reader or
the parity receipt requirement. The upgraded field contains the original
verified transcript hash, exactly as fresh information activation and recovery
already store it; no signed identity, payload, attempt or verification hash is
replaced, and no wire/schema version changes.

Node resolves the canonical bounded `coding-transcript` record by the physical
object's original attempt ID. It requires its exact original hash, replays the
full signed coding witness, verifies the assigned local nonvirtual information
role and checks the actual storage ID, role index, guild and full Merkle
commitment. An independently frozen original-history view authenticates the
plan against its original indexed membership roster. Expiry and later removal
do not invalidate historical evidence; this never authorizes a new attempt or
new protection claim. A valid different transcript cannot substitute for the
original. Empty parity evidence remains damage and is rejected even when its
transcript otherwise verifies.

This path requires complete original-history indexing and independently checks
original genesis, compact current authority, original tail and index marker
around successful lookups. It never materializes unused flat history or falls
back to a group-key witness. Missing original activation witnesses must be
recovered before evacuation; absent/incomplete indexes must finish their
existing original-event replay. Missing, oversized or corrupt witnesses,
rosters and activation metadata preserve the legacy READY bytes and locator.
Existing witness recovery can restore the exact original attempt record; a new
receipt or later coding group's evidence is not a substitute.

The control immediate writer excludes concurrent custody acquisition and
destructive work while one bounded volume writer reads the actual candidate,
authenticates it, conditionally fills only its empty marker and reads back the
exact complete object. Independent checks run before and after mutation, with
another exact physical readback after the final guard. Ignored SQL updates,
changed bytes or activation identities and late authentication failures roll
back the marker. Fixed-size activation fields and the 64 KiB receipt limit are
checked in SQL before allocation; source payloads and original transcripts keep
their existing bounds. No whole-volume/history collection is introduced.

An interruption immediately after upgrade leaves an independently usable
original marker. Reopen resumes ordinary verified evacuation even if the local
attempt witness subsequently becomes unavailable. Destination verification,
source withdrawal, pending operations, offline copies, shared checkpoint pins
and repair continue through their existing durable lifecycle. The broader
cooperative worker, archive accounting, native upgrade, quota and actual
retained-capacity/platform/topology/release gates remain separate M6 work.

Qualification closes the reopened R4 historical-information item: the full
ordinary store suite passes 276 tests (26 ignored), and the selected Node
authority/volume/real-upload evacuation suite passes 82 tests (one ignored).
The ignored physical headroom case separately passes on disposable Btrfs, as do
all three information/parity/legacy custody lifecycles; mount, loop-device and
image cleanup is verified. The legacy lifecycle uses an expired original plan
after membership removal and real source directory removal, then checks repair,
shared owners and final collection. Negative cases cover missing/oversized or
substituted witnesses, absent indexing, corrupt original rosters, parity damage,
SQL faults, competing volume writers and late authentication failure. Reopen
after the marker commit succeeds even without the local attempt witness.
Formatting and strict workspace/all-targets Clippy pass. M6 remains open for
R1/R2/R3/R5/R7; these local regressions do not replace installed-artifact,
native/platform/topology or retained 1 TiB qualification.

## Durable encoded-page storage reservations (2026-10-10)

The immutable page store now supports an explicitly configured durable quota
for encoded page bytes, distinct stored pages and open reservations. Initial
adoption counts existing physical page rows using SQL lengths, without loading
their blobs or granting source, signature or ownership authority. Resizing must
fit all stored pages and outstanding credits. A separate enabled marker makes
missing or malformed ledger state an error.

`begin_catalog_with_page_reservation` binds fixed byte/page credits to the exact
immutable intent. An immediate writer transaction reserves capacity and creates
the intent together. Concurrent connections cannot overbook that ledger. Exact
replay preserves the original reservation; changed scope, section or capacity,
cancelled IDs and overflowing/exhausted dimensions are rejected. Configured
Building intents require a reservation before staging, including intents that
predate initial quota adoption. Existing published catalogs keep their read and
retirement paths.

New encoded pages convert reserved credits into stored usage in the same
transaction as page bytes, metadata and construction ownership. Reused physical
pages consume no new credits. Root or bundle publication and cancellation close
unused credits atomically with their existing state changes. Construction-pin
release does not reduce stored usage: shared roots and parent closures retain
their charge until the final owner retires and ordinary GC actually deletes each
page. There is no per-forest budget reset. Bounded canonical records, exact
write/readback checks and transaction rollback detect ignored or reverted SQL
updates, missing insertions and ignored page collection.

These counters cover encoded page blobs. SQL/WAL overhead, source/parity
payloads, traversal work, logical retained data and dataset/history/guild limits
still need the complete enclosing policy. Explicit configuration preserves the
existing foundation behavior before that policy is installed. Normal paged
producers remain disabled. Original intent/page/bundle and signed wire layouts
are unchanged. Closed reservation rows and cancelled intent tombstones remain
until verified generation-floor retirement is implemented.

Qualification passes 509 distinct cases: all 175 core and 301 ordinary store
tests, 32 paged Node tests and the provisioned native retained sparse-tree
capture/migration/recovery regression. Ordinary store and selected Node runs
retain 26 and one ignored cases respectively; the named native case is run and
counted separately. It passes in 32.21 seconds with independent mount, image and
loop cleanup verified. This native regression uses the existing unconfigured
migration path. Seven new configured store fixtures exercise simultaneous and
competing connections, exact replay/reopen, independent byte/page exhaustion,
existing-page adoption, shared parent/root closures, atomic bundle publication
and cancellation, corrupt/missing records and ignored/reverted SQL faults.
Formatting, strict locked workspace/all-targets Clippy, all-target test
compilation and all four debug program builds pass. The frozen Rust/Cargo source
and seven program/test-driver hashes remain unchanged. Logs, manifests, passed
case inventory and cleanup evidence are retained in
`/tmp/mb-m6-storage-quota-validation-o6anvf3v`. These checks qualify this page
storage increment; normal producer activation, complete R2/R3 capacity and
quotas, generation floors, installed-artifact/platform/topology and real retained
1 TiB gates remain open.

## Atomic retained migration page admission (2026-10-10)

The store can now reserve every role of one bounded same-scope bundle under
one immediate transaction. Requests reject duplicate IDs, mixed scopes and more
than the existing sixteen bundle roles before mutation. A checked callback can
write its immutable owner journal in that same transaction using ordinary
record reads/CAS/writes, without nested transactions or external I/O. Quota,
late role, callback or ignored-write failures roll back every earlier reservation
and journal write. Each original per-intent capacity remains immutable on replay.
Quota status reads both the enabled marker and ledger in one read snapshot.

The explicit retained legacy migration now uses this admission path whenever
the store has encoded-page quotas enabled. Its existing authenticated native/Git
dry run counts emitted encoded bytes/pages in six fixed role counters. Complete
original source/schema/Git byte validation and typed-root validation precede
admission. Source credits conservatively cover the framed record maximum for
every legacy data source, emitted private page and bootstrap sector, with full
leaf/index geometry and the encoded page maximum. This can reserve more than
the eventual deduplicated storage; publication returns the unused credits.
Absent Git roles acquire no reservation.

Migration binds all three or six roles and its exact original journal in the
same writer transaction before external page staging. Unconfigured stores also
delay journal creation until that authenticated preflight has passed. Completed
replay keeps its existing read-only source behavior and original identities.
After admission, interrupted writes remain owned and resumable; cleanup rebuilds
the disposable source ordering queue only after successful admission.

`fence_catalog` can persist exact cancellation for a role that was never reached
or for an unreserved Building intent predating quota adoption. It acquires no
new credits, preserves bundled/source-owner cancellation guards and releases
existing unused credits through the same ordinary state transaction. Migration
cancellation applies it to every deterministic role, including absent Git roles;
cleanup and actual final-owner GC retain their existing bounded steps. Cancelled
IDs and closed reservation records keep their generation-floor tombstones.

This connects encoded-page admission to existing retained migration. The full
dataset/history/guild policy, SQL/WAL and payload headroom, traversal work,
normal paged capture/packing/checkpoint/retention/seed consumers and real dense
retained 1 TiB qualification remain required. Original signed/page/intent/bundle
layouts and flat production heads remain unchanged.

Qualification passes all 175 core and 303 ordinary store cases, 34 ordinary
paged Node cases, the ordinary certified-writer migration entry point and the
quota-enabled native retained capture/recovery fixture (514 distinct cases).
The provisioned native case passes in 28.31 seconds on disposable Btrfs and
verifies shared migration storage before source loss and retained repair.
The new fixtures cover late-role and owner-journal rollback, cancellation of
unreached/pre-quota intents, real framed source-tree boundaries, and admission,
interruption, reopen and cancellation through authenticated legacy migration.
Existing migration fixtures for formats 1/3/4/5 now exercise configured quota
publication, shared pages and final-owner GC. The ordinary suites exclude 26
store cases and one selected native case; that native case is run separately.
Formatting, strict locked workspace/all-targets Clippy, all-target test
compilation and four debug program builds pass. Frozen Rust/Cargo source and
seven program/test-driver hashes remain unchanged; mount/image/loop cleanup is
verified. Logs, both drivers, manifests and the complete passing-case inventory
are retained in `/tmp/mb-m6-page-admission-validation-lqep397s`. This is a focused
debug-source qualification, not complete ordinary/native or installed-artifact
qualification. The user deferred real dense 1 TiB and native Windows/macOS
qualification on 2026-10-10 until implementation/other items are ready and
external resources are available; those acceptance gates remain open.

## Retained data-source reservations (2026-10-10)

The local page ledger now composes with a separate dataset-wide source quota.
Its version-one policy applies independently to each dataset scope. Logical
source bytes count each exact authenticated data sector once across all retained
paged revisions in that dataset. Hard-link/native/Git reuse and unchanged
history can share a source charge; other protected roots are independently
billed. This metric excludes sparse file holes and alias lengths, private pages,
bootstrap metadata, encoded catalog storage and physical coding/parity payloads.
Those remain separate enclosing policy dimensions.

Explicit legacy migration reserves its complete original data-source upper
bound in the same writer as all page roles and its immutable journal, after
authenticated preflight. A late data-quota failure rolls back the page prefix.
Source publication converts only newly retained identities from reserved to
stored credits in the same transaction as the source recipe, native anchor pin,
root bundle and publication marker. Shared sources consume no new credits.
Migration's conservative original-source reservation can require temporary
headroom even when publication will share existing sources. Exact incremental
admission must also retain every shared dependency across its admission/publication
interval; skipping credits after an unpinned lookup would race retirement.
Publication returns every unused credit; cancellation closes open reservations
and permanently fences the ID. Already published data remains charged until
bounded source-binding cleanup releases its last retained owner. Repair and
checked source-location replacement keep the same identity/charge.

Reads verify the policy marker, bounded canonical ledger/reservation/charge,
scope, original capacity, exact source commitment and owner count. Ignored or
reverted writes fail closed under their enclosing writer. A dedicated error
names source-quota exhaustion and its cleanup/increase remedy. Policy limits
can grow without scanning every dataset; reductions reject. Initial enablement
rejects any existing paged data binding or stale accounting record before
mutation. Existing flat sources acquire charges through authenticated explicit
migration; bounded adoption of existing paged bindings and full retained flat
history accounting remain required. Closed IDs await verified generation floors.

The ordinary legacy-format and provisioned native recovery fixtures use both
quotas. Qualification passes 175 core, 307 ordinary store and 34 paged Node
cases, the ordinary certified-writer migration entry point, and the provisioned
native capture/recovery fixture (518 distinct cases). Four new store fixtures
cover simultaneous connections, exact replay, independent dimensions/datasets,
sharing and final-owner cleanup, cancellation fences, read-only/reopen behavior,
1 TiB reservation arithmetic, SQL faults, initial adoption rejection and
missing/corrupt accounting, including loss of both policy records. The arithmetic
fixture reserves counters only; it does not store or recover a dense 1 TiB.
Legacy formats 1/3/4/5 exercise configured sharing and final cleanup; existing
interruption cases cover joint data/page/journal admission and rollback of
source binding and credits with an ignored publication marker.

Native qualification passes in 36.49 seconds on disposable Btrfs. It checks
deduplicated bytes/counts against unique original source IDs, both shared
migrations, exact native restore, original source loss and retained checked
repair. The earlier native run failed a new assertion that summed repeated
signed references instead of unique identities; correcting that oracle leaves
production accounting unchanged. Its cleanup also completed. An earlier compile
run was deliberately stopped to harden loss of both quota-policy records; neither
earlier run counts toward qualification. The ordinary suites exclude 26 store
cases and one selected native case, which is provisioned separately.

Formatting, strict locked workspace/all-targets Clippy, all-target test
compilation and four debug program builds pass. Frozen Rust/Cargo source and
seven program/test-driver hashes remain unchanged; native mount/image/loop
cleanup is verified. Logs, both drivers, manifests, complete passing-case
inventory and independent audits are retained under
`/tmp/mb-m6-retained-source-validation-za4kq3hy`. This is focused debug-source
qualification; other ordinary/native suites and installed artifacts were not
rerun. Normal producers, enclosing metadata/work
geometry, sparse/file/Git logical size policy, physical payload/headroom, guild
quotas, complete history ownership, installed-artifact/platform/topology and
real retained 1 TiB gates remain open.

## Budgeted retained checkpoint authority (2026-10-10)

Retained source sharing cannot remove traversal debt. A checkpoint referring
to unchanged revisions still has to authenticate each signed source-tree
occurrence. The original authority root applied its 16 GiB/one-million-page
aggregate cap across that history, independently of the supplied enclosing
proof budget. That ceiling blocked multiple dense 1 TiB revisions even when
their physical data and immutable pages were shared.

Authority format two preserves the original ordered fields, authority records,
page format, signed revision bytes and individual tree limits. Explicitly
budgeted construction, decoding and traversal admit the cumulative referenced
body/source bytes, pages and record work. The control stream remains bounded
by its original tree/record ceilings. Each referenced legacy envelope retains
its original 32 MiB limit; each paged source tree retains its 16 GiB and
one-million-page limit. Summary bounds also enforce these per-reference maxima
with checked arithmetic, even when the independently supplied budget is large.
The original unbudgeted APIs and format-one root retain their previous limits.

The new root reserves a fixed 1 KiB envelope. Construction checks future dense
control/index work before writing each frame. Decoding checks the complete
declared byte/page debt before any fetch; traversal reserves all outer records
and legacy-envelope records before admitting a paged source-frame count and
exposing its revision. Trailing bindings/attestations cannot lend their record
credits to a referenced source closure. Understated summaries reject before
exposing the offending reference, and errors permanently fence that reader or
builder. The full store join still authenticates all body/source EOFs and
charges flat legacy source entries against the same budget.

The local authority-proof descriptor selects format two for these roots. Draft
paged checkpoint format nine requires authority format two, while format eight
continues to require format one. Field orders and signing/hash domains remain
unchanged; each version is part of its signed body. The public join, certified
history transition, exact quorum binding and guarded enclosing owner carry the
same trusted budget. Original event authority, current predecessor checks,
local typed EOF, replay, cancellation and bounded root release remain required.
The standalone format-one authority-retention journal stays at its old limits;
the guarded paged owner retains the new format. Normal producers remain off.

Six new fixtures cover cumulative declared source geometry for 32 retained
1 TiB revisions, exact and exhausted dimensions, pre-exposure debt for trailing
authority phases, corrupt/unsupported summaries and canonical decoding,
original root layout, version-bound header/quorum checks, complete actual
mixed-source joins, original-history ownership and Node reopen/cancellation.
The large-geometry fixture signs and streams real small authority records but
does not materialize or recover its claimed dense source trees. It is admission
arithmetic and codec coverage, not retained-capacity qualification.

Qualification passes all 178 core and 309 ordinary store tests, 35 paged Node
cases, the ordinary certified-writer retained-migration entry point and the
provisioned Btrfs retained native capture/recovery fixture (524 distinct tests).
The ordinary suites exclude 26 store cases and one selected native case,
provisioned separately. The paged-module selection already includes the
legacy-information activation/custody/evacuation case; the distinct inventory
counts it once. Formatting, strict locked workspace/all-targets Clippy,
all-target test compilation and all four debug program builds pass under
Cargo/rustc 1.99.0. Frozen Rust/Cargo source, seven binaries and 21 unchanged
embedded protocol/helper inputs match in the independent audit. Native mount,
loop and image cleanup is verified. The first harness stopped before creating
its fixture because Btrfs tools were absent from the turn's PATH; qualification
resumed with the installed Nix tools against the same frozen binaries. Both
the initial harness evidence and resume driver are retained. Logs, manifests,
the complete distinct passing-case inventory and audits are in
`/tmp/mb-m6-history-admission-validation-zjwq8pri`. This is focused debug-source
qualification; other ordinary/native suites and installed artifacts were not
rerun.

Full private/bootstrap/payload
and SQL/WAL headroom, dataset/history/guild policy, exact incremental sharing,
normal capture/packing/coding/checkpoint/retention/seed-only recovery, native
platforms, topology diagnosis and installed-artifact gates remain open. The
user-deferred real dense 1 TiB run remains a separate acceptance gate.


## Incremental retained-source dependency admission (2026-10-10)

A conservative full-source loan prevented an unchanged second revision from
being admitted at the dataset limit, although publication charged its shared
identities once. Merely subtracting already charged sources would leave a race:
the original owner's final cleanup could remove both the charge and physical
native anchor before the new revision published.

Explicit retained migration now passes its complete authenticated, deduplicated
data records from the existing dry run into source admission. The store accepts
a repeatable iterator of strictly increasing unique identities, validates each
bounded record, and hashes the complete input. The existing immediate writer
reserves only new logical bytes/source counts and creates dependency holds for
shared identities, together with all page reservations and the immutable
migration journal. No external byte reads occur in that writer. Open-operation
limits are checked before the input walk. Any input, quota, journal or SQL fault
rolls back the complete admission.

Each bounded hold has a dataset/source/operation key and an operation backlink.
It increments the existing source owner count and the native anchor pin count.
A hold can borrow a surviving hold after the original revision's final binding
has been cleaned. It preserves local ownership, without creating a published
data recipe or new source authorization. Existing source and reservation record
layouts, original signed legacy bytes, source addresses and page roots remain
unchanged. An immutable admission plan fences changed input retries. Existing
conservative Building reservations keep their original loans on resume and
acquire the same dependency holds for their newly authenticated shared inputs.

Authenticated publication creates the new data binding and physical pin, then
consumes its matching hold in the same writer. Unconsumed holds reject closure
before a publication marker can commit. The new binding can use a verified
replacement anchor, while the old hold protects the old anchor until transfer.
Cancellation fences the reservation and releases unused loans; each subsequent
cleanup step releases at most one hold, including operations without a bundle.
Sources stay charged until their final binding or hold is actually removed.
Readback checks reject ignored or reverted hold, charge and anchor-pin writes.
A separate retained-fact accessor requires the bundle-selected Verified or
Cancelled validation state. Ordinary source serving still requires Verified
state. The cancelled-binding regression reproduced the active-validation lookup
failure before this correction and passes afterward.

Six new store fixtures cover exact-capacity sharing, original final-owner
cleanup, cancelled bindings awaiting cleanup, reopening, hold-to-hold borrowing,
competing connections publishing
and cancelling, changed/nonrepeatable inputs, conservative replay, owner-journal
rollback, SQL faults, and failed publication/cancellation pin transfers. Legacy
formats 1/3/4/5 now repeat real migration at exactly one dataset's byte/source
capacity. The provisioned native capture/recovery fixture uses its unique data
bytes and source count as the exact limit, including repeated signed source IDs.
Frozen qualification passes all 178 core and 315 ordinary store tests, 35
paged Node cases, the ordinary certified-writer migration entry point and the
provisioned Btrfs retained native capture/recovery fixture (530 distinct cases).
The ordinary suites exclude 26 store cases and the selected native case,
provisioned separately. The passing inventory counts the paged-module legacy
information activation/custody case once. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and all four debug program
builds pass under Cargo/rustc 1.99.0. Source and seven binary hashes remain
unchanged; 21 embedded protocol/helper inputs match in the independent audit.
Native mount, image and loop cleanup is verified. Logs, manifests, the complete
distinct inventory, the negative cancellation reproduction and final audits
are in `/tmp/mb-m6-source-dependencies-validation-kw33d3cx`. This is focused
debug-source qualification; other ordinary/native suites and installed artifacts
were not rerun.

After qualification, removing only rebuildable incremental caches reclaims
11 GiB and leaves about 50 GiB in `target`; the seven qualified binary hashes
remain unchanged. The cleanup record and before/after sizes are retained with
the final audit.

This closes incremental source admission for explicit retained migration. It
counts unique non-hole data-source logical bytes; sparse file length, aliases,
private/bootstrap metadata, physical padding/parity/payload and SQL/WAL remain
separate policy work. Full dataset/history/guild metadata admission, bounded
existing-paged adoption, generation floors, normal paged producers and seed-only
recovery, topology diagnosis and installed/platform gates remain open. The
user-deferred dense 1 TiB and native platform runs remain separate acceptance
gates.


## Shared local data recipe ownership (2026-10-10)

Inline local data bindings copied each opaque recipe into every retained
revision. At the supported 8 KiB recipe limit, 32 dense 1 TiB references could
copy 4 TiB of recipe values alone. Logical source sharing and public traversal
budgets did not reduce that local metadata debt.

New bindings use local format three: source, anchor, a 32-byte shared recipe
identity and the owner-specific generation. They encode within 256 bytes. The
shared identity hashes a versioned canonical tuple of dataset scope, complete
source identity/commitment, anchor and exact opaque recipe bytes. Generation is
excluded, so repairs remain independent per owner. One bounded dictionary
record retains the original recipe bytes and a reference count. A fixed
owner backlink prevents double acquisition and permits exact final-owner
cleanup. Reads check the digest, canonical encoding, expected scope/source/
anchor, owner backlink and complete reference count before returning bytes.

Publication adds the dictionary reference and owner binding in the same writer
as source accounting and physical pins. Existing version-one/two bindings
replay unchanged, and shared bindings replay without another reference.
Replacement acquires its new identity, changes the generation-fenced owner
binding, releases its old shared reference and transfers native pins atomically.
Other owners keep their bytes, locator and generation. Cancellation hides the
owner immediately; its recipe remains retained until actual bounded binding
cleanup. The dictionary is removed only after its final backlink is removed.
Readback checks reject ignored/reverted inserts, updates and deletes.

Versions one and two retain their exact layouts and opaque bytes. Their bounded
byte deserializer shares format three's 8 KiB limit and rejects oversized or
impossible length declarations before allocation. Older inline bindings can
transfer to shared format during an authenticated replacement; this does not
rewrite untouched legacy bindings or original signed revisions/page roots.
Test fixtures explicitly retain inline states when qualifying original layouts.

Four new fixtures build 32 real small signed local catalogs sharing an actual
8 KiB recipe, then verify replay, reopen and final-owner cleanup. They exercise
independent repairs joining existing recipes, stale/exact retries, physical pin
conservation, SQL faults and corrupt/missing dependencies. The old version-one
replay and generation-exhaustion fixtures remain qualified with inline records.
The dense calculation bounds shared recipe plus owner-binding values below
512 GiB instead of 4 TiB of repeated recipes. It is encoded-value arithmetic,
not SQL/index/WAL or dense-data qualification. Distinct locators/recipes remain
distinct; callers cannot collapse independently retained source replicas.
Frozen qualification passes all 178 core and 319 ordinary store tests, 35
paged Node cases, the certified-writer migration entry point and provisioned
Btrfs retained native capture/recovery (534 distinct cases). The ordinary
suites exclude 26 store cases and the selected native case, provisioned
separately. The inventory includes the legacy-information activation/custody
case once. Formatting, strict locked workspace/all-targets Clippy, all-target
test compilation and four debug builds pass under Cargo/rustc 1.99.0. Source
and seven binary hashes remain unchanged; 21 embedded protocol/helper inputs
match in the independent audit. Native mount/image/loop cleanup is verified.
Logs, manifests, passing-case inventory and final audits are in
`/tmp/mb-m6-shared-recipes-validation-bcp0vuql`. Other ordinary/native suites
and installed artifacts were not rerun.

Removing rebuildable incremental caches after qualification reclaims about
8 GiB, leaving about 50 GiB in `target`. Qualified binary hashes remain
unchanged; cleanup sizes and the final audit are retained with the evidence.

Complete section/dataset/guild metadata admission must still fund owner keys,
indexes, backlinks, source validation, capture manifests, shared pages, packing/
coding, scratch and WAL/payload headroom. Legacy adoption and normal paged
capture/retention/seed recovery remain required. The user-deferred dense 1 TiB
and Windows/macOS runs remain open acceptance gates.

## Explicit enclosing packing admission (2026-10-10)

The two packing record trees are each bounded by 16 GiB and one million page
occurrences. The original local packing descriptor also imposed those ceilings
on their sum. That aggregate restriction can reject independently valid streams
before the enclosing checkpoint policy can account for their complete work.

Local descriptor format two requires a separately supplied trusted
`CatalogCodingTraversalBudget`; it cannot obtain its limits from its own root
claims. The budget pays both tree occurrences, both framed record counts and
the canonical descriptor before any page fetch or source authorization. Each
original tree keeps its existing schema, scope, bounds and authenticated root.
Format one and the original unbudgeted decode/build/certified-join APIs preserve
their aggregate limits. A large supplied budget cannot relax a stream limit or
silently upgrade a format-one descriptor. Original signed revision/checkpoint
bytes, packing roots and source identities remain unchanged.

The completed index retains its trusted remaining budget and requires it as
well as the completion marker before lookups or local bundle construction.
Explicit legacy-certified joins subtract their admitted source-authority work
first. Public checkpoint joins subtract the same retained authority debt and
reserve their combined descriptor. Complete coding-directory joins retain all
three dimensions of prior work and fund every packing/coding stream. Original
single-forest APIs remain bounded by their original contract. Durable physical
scratch/page admission and authenticated source authority remain separate.

Four new fixtures cover each exhausted dimension before I/O, canonical and
version bounds, truncated source/descriptor inputs, missing trusted admission,
original aggregate limits, independent stream limits, certified authority debt
and complete directory witness seeks. One fixture validates declared full-stream
upper bounds without materializing large streams or payload. Existing public
mixed-source joins use format two, and budgeted guarded checkpoint fixtures
carry it through certified original-history proof, retained ownership, reopen
and bounded cancellation. Frozen qualification passes 178 core, 323 ordinary
store and 35 paged Node cases, the certified-writer migration entry point and
provisioned Btrfs native capture/recovery: 538 distinct cases. The ordinary
suites leave 26 store cases ignored; the selected ignored native case runs
separately on a disposable 2 GiB filesystem with a logical sparse 1 TiB file.
This is not dense-capacity qualification. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and four debug builds pass under
Cargo/rustc 1.99.0. Frozen source, seven binaries and 21 embedded protocol/helper
inputs match. Native mount/loop/image cleanup is verified. Logs, manifests and
the distinct passing-case inventory are retained under
`/tmp/mb-m6-packing-admission-validation-zcytodje`. Other ordinary/native suites
and installed artifacts were not rerun.

Removing rebuildable incremental caches reclaims about 7.6 GiB, leaving about
50 GiB in `target`. Qualified binary hashes remain unchanged; cleanup sizes
and final independent audits are retained with the qualification evidence.

The full section/dataset/guild metadata policy must still derive and fund the
required single-owner retained geometry, private metadata, data bindings,
validation facts, capture manifests, physical pages, scratch and SQL/WAL/payload
headroom. Normal paged producers/retention/seed recovery and deferred dense
capacity/native-platform qualification remain required.

## Current installed Linux artifact qualification (2026-10-10)

Committed source `c4efb51` builds successfully as the actual Nix musl runtime
and optional Git alias. Two fresh disposable Btrfs fixtures qualify the same
installed candidate and frozen process drivers. Both runs pass all three
isolated-PATH Git packaging scenarios: ordinary import/fetch/push, alias-first
operation and standalone missing-Git rejection before refs/history change.
Each process run passes 23 ordinary cases, raw Unix CLI/daemon/Git paths, the
stock-Git bridge and five-daemon topology/seed recovery. There are 26 distinct
process cases and 52 executions across the two runs. The topology gates pass
in 679.73 and 597.27 seconds, with source/storage loss, direct and punched paths,
relay-only replacement and final verified backup.

Live `/proc/PID/exe` observations bind all five topology daemon roles to the
installed static payload in each run. Separate final audits verify tracked
source, eight runtime wrappers/payloads, the alias and both compiled drivers;
source/candidate/driver hashes are identical across runs. Each run preserves
eight named daemon logs with private directory/file modes. Disposable mounts,
images, loop associations, namespaces and fixture firewall rules are retired,
and forwarding returns to its initial value. Provisioning manifests and
independent audits report success under
`/tmp/mb-m6-installed-c4efb51-1_ha0nbo` and
`/tmp/mb-m6-installed-repeat-c4efb51-m3pnuksl`. Build inputs and Nix store roots
are recorded; earlier qualified installed candidates remain rooted separately.

Retained daemon logs contain 46 and 44 per-daemon event groups with incomplete
signature sets followed by complete sets. Their longest observed intervals are
116.76 and 103.39 seconds. These are bounded observations of available logs;
they do not prove unlogged phases, diagnose the original 5,400-second outlier,
or qualify the required partition/coordinator-crash/interrupted-retry matrix.
R5 stays open. This is the listed installed Linux slice, not the full R7 native,
upgrade, multi-volume, private-Tor, supported-platform or retained-capacity
matrix. The enclosing metadata policy and normal paged producer/recovery path
also remain required before production admission is enabled.

## Aggregate retained logical-source guild admission (2026-10-10)

Independent dataset limits allow several owners or protected roots in one guild
to reserve their entire limit concurrently. The new explicit
`configure_catalog_retained_source_guild_quota` policy limits their combined
retained logical data-source bytes, unique per-dataset sources and open jobs.
Every dataset counter change applies its exact old/new delta to the guild ledger
inside the same page/source/owner-journal writer. Publication converts credits;
sharing and native source-location repair add no duplicate charge. Cancellation
returns unused credits but preserves stored source charges until actual final
binding or dependency-hold cleanup. Existing signed records and dataset quota
encodings are unchanged; stores without a configured guild policy keep their
existing limits.

Initial activation streams existing accounted dataset ledgers under the
immediate writer. SQL bounds each key/value before row allocation; memory does
not grow with dataset, revision, source or page counts. Stored cancelled sources
and outstanding reservations participate in adoption. An over-limit guild,
missing marker, malformed scope/key/encoding or oversized row rolls back the
whole activation without changing existing sources or jobs. Grow-only resizing
preserves outstanding admission without a history scan. Durable guild/dataset
membership prevents a missing ledger pair from becoming new zero usage; point
reads verify policy/marker/ledger membership and dataset inclusion. Ignored or
reverted SQL writes must fail and roll back both ledgers with the enclosing
owner transaction. The aggregate accessor reports a Guild scope; repeated source
identities in separate dataset scopes retain their existing independent charges.

Six new Store regressions cover competing datasets/owners/connections, separate
byte/count/job exhaustion, independent guilds, immutable replay, adoption of
stored/cancelled/outstanding usage, reopen/read-only behavior, grow-only changes,
SQL faults throughout activation/publication/cancellation/final cleanup and
malformed or missing accounting. Existing dependency-hold fixtures now enforce
the same guild limit, including original-owner cleanup before hold-to-hold
borrowing/publication and interrupted cancellation. The provisioned Btrfs native
fixture enforces exact dataset and guild limits through shared retained migration,
source loss, rejected corrupt repair, interrupted replacement, reopen and retry;
the aggregate charge remains unchanged. Frozen qualification passes 178 core,
329 ordinary Store and 35 paged Node cases, the certified-writer migration entry
point and provisioned native recovery: 544 distinct passing cases. Formatting,
strict locked workspace/all-targets Clippy, all-target test compilation and all
four debug program builds pass under Cargo/rustc 1.99.0. Frozen source, seven
binaries and 21 embedded protocol/helper inputs match through qualification.
Native mount/loop/image cleanup is independently checked. Evidence is retained
under `/tmp/mb-m6-guild-source-validation-if3dgpyt`; the post-commit audit binds
the qualified source and embedded inputs to the commit. Removing only disposable
incremental caches reclaims 7.48 GiB and leaves about 51.2 GiB in `target`, with
all qualified binary hashes preserved.

These limits count non-hole authenticated data-source logical bytes. They do not
fund private/bootstrap metadata, padding, parity/coding payloads, SQL/WAL or
traversal/scratch. Adopting previously unaccounted paged data remains separate
from activating a guild limit over existing dataset accounting. Complete section/
dataset/guild metadata and physical policy, normal paged producers/recovery,
generation-floor retirement and deferred real capacity/platform qualification
remain required before production admission is enabled.

## Sharded original packing streams (2026-10-10)

A single retained owner can exceed both original packing stream record limits.
The declared geometry fixture includes 16,777,216 dense data sources and 32
maximum private catalogs, each with one million page sources plus a bootstrap
source: 48,777,248 sources total. Preserving the allocator's reserved cross-owner
slot requires 65,036,331 packed sectors. At two frames per source/descriptor,
both streams exceed their existing 67,108,864-record cap. The fixture materializes
four bounded root records, representing two source and two descriptor parts.
It verifies declared directory admission, without storing those nested streams
or payload and without qualifying real dense capacity.

`CatalogPackingDirectoryRoot` adds bounded source ranges followed by contiguous
global descriptor ranges. Each original stream keeps its byte/page/record caps;
the enclosing trusted budget charges all referenced occurrences and directory
framing before page I/O. One active nested reader verifies actual first/last
source headers, part totals and every nested and directory EOF. Global sector
indices remain in the original identity calculation across boundaries.
Interior padding-only parts are allowed, while the complete stream must still
end with a sector containing a source. Original whole-stream formats retain
their existing meaning, and signed layouts remain unchanged.

`CatalogPackingDirectoryIndex` shares the original packing join engine inside
one admitted private scratch transaction. Source authorization, uniqueness,
missing-chunk accounting, virtual-zero checks and Merkle composition continue
across every part boundary. Bounded point lookups require the exact completed
directory marker. A failed source, part, authority, SQL write or physical scratch
admission rolls back the whole index prefix. The reader does not collect a
whole directory or reset budgets between parts. Eleven new core/Store cases
cover declared geometry, original IDs/global indices, both source encodings,
interior padding, range/EOF/canonical bounds, pre-I/O dimensional exhaustion,
cross-part duplication, false zero/Merkle substitution, ignored writes and
scratch exhaustion/rebuild. The fixture with 2,048 sources exercises directory
index pages and spills beyond its one MiB cache.

Frozen qualification passes 185 core, 333 ordinary Store and 35 paged
Node cases, the certified-writer migration entry point and provisioned Btrfs
native capture/recovery: 555 distinct cases. The ordinary suites leave 26 Store
cases and one Node case ignored; that native case runs separately on disposable
Btrfs with a logical sparse 1 TiB file. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and four debug builds pass under
Cargo/rustc 1.99.0. Frozen source, seven binaries and 21 embedded protocol/helper
inputs match; native mount/loop/image cleanup is verified. Evidence is retained
under `/tmp/mb-m6-packing-shards-validation-newgl31k`. The post-commit audit
binds source and embedded inputs to the commit. Removing only rebuildable
incremental caches reclaims 8.61 GiB and leaves about 51.3 GiB in `target`, preserving
all seven qualified binary hashes. Other ordinary/native suites and installed
artifacts were not rerun.

This stages the sharded join. Transitive durable ownership of referenced parts,
certified authority/coding/public joins and checkpoint activation still need
integration. The index intentionally offers no directory-only local bundle,
which would leave nested parts without ownership. Full section/dataset/guild
policy must fund private/bootstrap metadata, sources, payload, SQL/WAL and
physical traversal/scratch headroom before enabling normal producers. The
normal paged capture/retention/seed-recovery path and deferred dense-capacity/
native-platform qualification gates remain open under R3-SINGLE-OWNER-METADATA.

## Certified sharded packing/coding and transitive ownership (2026-10-10)

The original coding-directory and local combined owner required two individual
packing roots. `CatalogPackingCodingDirectoriesValidation` now admits a packing
directory and a coding directory under one trusted remaining budget. Its
separate local format charges source-authority debt, both directories, every
referenced stream occurrence and a conservative combined envelope. Exhaustion
of any byte/page/record dimension fails before coding page I/O or authorization.
The original packing/coding descriptors and signed layouts remain unchanged.

`CatalogPackingCodingDirectoriesIndex` reuses the original sector-coverage,
current/historical authorization and bounded witness-row checks in the same
admitted private scratch store. All groups and both directories must reach
complete EOF, and every packed sector must have qualifying active coverage.
Only the exact completed marker admits coverage lookups, ordered group seeks
or authenticated witness replay; replay also reports its additional work.
An ignored SQL write, damaged tail, missing coverage or denied authority rolls
back the whole coding prefix while preserving the completed packing index.

The legacy certificate/source-authority bridge now validates sharded packing
without resetting imported authority debt, weakening exact source cardinality
or substituting source commitments. The certified wrappers carry the original
trusted base, signed candidate cursor and debt through the complete coding join.
This is the existing migration bridge and required external coding-authority
callback; it does not certify the enclosing paged public/private checkpoint.

`CatalogPackingCodingDirectoriesRetention` pins both directory roots atomically.
The packing reader's new part visitor pins each admitted source/descriptor root
before nested evidence traversal, and the existing coding visitor pins every
forest part. Short immediate transactions own those pins and counters; the
walkers hold no production writer. Publication follows every local EOF and
rechecks the completed proof. Immutable interrupted jobs resume through reopen;
changed jobs and cancelled identifiers cannot reacquire ownership. The shared
retention journal uses a new kind and pin prefix five, preserving earlier
journal and pin layouts. Release retires at most one cancelled root closure per
transaction. Shared owners preserve all parts until their own final cleanup.
This owner covers packing/coding metadata; authority/private/bootstrap/native
and information/parity payload custody still belong to the enclosing checkpoint.

Eleven new core/Store cases cover part visits before I/O and permanent failure
fencing, dimensional exhaustion, certified scope/cardinality/commitment guards,
signed candidates carried through a nonempty coding witness, complete global
coverage and bounded seeks, damaged tails, ignored writes, interruption/reopen,
changed retries, shared retirement and atomic publication/release. Ownership
fixtures retain more roots than a local bundle can carry, retire original
staging intents, reopen and replay both packing and coding before final GC.
Frozen qualification passes 186 core, 343 ordinary Store and 35 paged Node
cases, the certified-writer migration entry point and provisioned Btrfs native
capture/recovery: 566 distinct cases. Ordinary suites leave 26 Store cases and
one Node case ignored; that native case runs separately on disposable Btrfs
with a logical sparse 1 TiB file. Formatting, strict locked workspace/all-targets
Clippy, all-target test compilation and four debug builds pass under Cargo/
rustc 1.99.0. Source, seven binaries and 21 embedded protocol/helper inputs match.
Native mount/loop/image cleanup is independently checked. Logs, manifests and
the distinct passing inventory are retained under
`/tmp/mb-m6-sharded-joins-validation-omq9ys8p`; the post-commit audit binds the
qualified source and embedded inputs to the commit. Removing only rebuildable
incremental caches reclaims 8.65 GiB and leaves about 51.4 GiB in
`target`, with all seven binary hashes unchanged. Other ordinary/native suites
and installed artifacts were not rerun.

Complete public/private checkpoint joins, certified-current activation and
successor retirement must still select and own these exact directories and all
other metadata/payload roles. Full section/dataset/guild metadata and physical
admission, normal paged capture/retention/seed recovery and deferred real dense
capacity/native-platform qualification remain open. This closes the local
source/coding join and transitive packing/coding metadata handoff, while
R3-SINGLE-OWNER-METADATA and Milestone 6 remain open.


## Public authority joins sharded packing and format-ten headers (2026-10-10)

The completed public authority proof now feeds the sharded packing/coding join
without flattening its parts or resetting the enclosing budget. Format-two
authority is mandatory. The adapter checks its completion marker, exact source
count and commitments, preserves the actual authority ledger, and reserves
packing/coding work before nested page I/O. Every original source, global sector
and coding EOF remains required. The resulting typed proof shares bounded mixed
legacy/paged revision cursors and point reads with the original public index.

A separate draft `PagedGuildCheckpointDirectory` and bounded quorum wrapper use
format ten. The header replaces the two individual packing roots with the
packing directory and requires authority root format two. Its 4 KiB header and
32 KiB certificate charge the public authority ledger and all nested packing/
coding occurrences under one supplied budget. Formats eight/nine retain their
original layout, limits and verification behavior. The deterministic shape-only
Postcard vector freezes the new layout; it is not complete body or capacity
qualification. Both quorum wrappers share the original strict signature checks.

`header_candidate` requires complete authority/packing/coding markers, current
coverage policy and the exact independent event/authority snapshot. It compares
every original Member record, including recovery key and failure domain, and
uses the completed authority record ledger. This is a candidate only. Certified
current coding state, legal original-history transition, live trust rereads,
private/bootstrap/native and information/parity ownership, atomic checkpoint
selection and successor retirement must still integrate the new proof before
production signing or activation. The normal producers remain disabled.

Eleven new cases cover bounded canonical/version decoding, incompatible original
formats, exact cumulative byte/page/record exhaustion, independent trust and
ledger guards, strict quorum/body binding, oversized nested lengths before
allocation, completed mixed-source/coding replay, pre-I/O scope/cardinality and
legacy-authority rejection, original authority debt, exact trusted members,
current policy/event checks, withdrawn completion markers, damaged tails and
suppressed SQL completion writes. Frozen qualification passes 191 core, 349
ordinary Store, 35 paged Node, the certified-writer migration entry point and
provisioned Btrfs native capture/recovery: 577 distinct cases. Ordinary suites
leave 26 Store and one Node case ignored; the native case runs separately on
disposable Btrfs with a logical sparse 1 TiB file. Formatting, strict locked
workspace/all-targets Clippy, all-target test compilation and four debug program
builds pass under Cargo/rustc 1.99.0. Frozen source, seven binaries and 22 embedded
protocol/helper inputs match. Native mount/loop/image cleanup is independently
checked. Logs, hashes and distinct case inventory are retained in
`/tmp/mb-m6-public-directories-validation-hwecyke4`; the post-commit audit binds
those inputs to the commit. Incremental-cache cleanup reclaims 8.93 GiB,
leaving about 51.4 GiB in `target`, with all qualified binary hashes
unchanged. Other ordinary/native suites and installed artifacts were not rerun.

Full section/dataset/guild metadata and physical admission, normal paged
capture/retention/seed recovery and the deferred real dense capacity/native
platform gates remain open. R3-SINGLE-OWNER-METADATA and Milestone 6 remain open.


## Certified directory checkpoints through original history and quorum (2026-10-10)

Format-ten candidates previously stopped before certified coding, authority
transition and quorum binding. The completed directory public index now enters
those same bounded algorithms as the original two-root layout. Private adapters
expose the exact header work, generation, global sector count and indexed
coding/sector/coverage rows. They create no flattened packing roots and no
constructor from a proposed header alone. Default generic proof types preserve
the original public APIs; new directory aliases carry the precise header and
certificate types through the completed chain. Existing signed headers, quorum
layouts and disposable marker schemas are unchanged.

The certified coding scan admits complete public input and conservative fixed
row work before original group lookups, requires exact retained/retired counts
and original lifecycle/profile/witness facts, and verifies current placement
for every globally indexed packed sector. The completed original-history route
carries its replay debt forward. Both layouts share authority comparisons for
retained signed revisions, tombstone floors and certified current writers, plus
exact event ancestry and historical coding-prefix comparisons. A directory
predecessor supplies its original quorum, header hash and complete index. Budget
admission charges both public inputs and comparison work without resetting debt;
an already admitted original-history ledger is not charged twice.

Directory transition proofs can sign their bounded public header and bind its
exact original quorum with independent trust rereads around key/binding work.
The wrapper rechecks the whole typed proof chain and exact certificate. As with
the existing draft bridge, authority-only transitions remain distinguishable by
`has_certified_history_transition`; guarded publication must require the full
history route. Signing is not checkpoint activation. Private/bootstrap/native
and information/parity payload joins, durable selection/retirement and normal
paged producers still need the directory proof. Existing production ownership
APIs continue to take the original layout.

Eleven new cases cover certified group omissions/substitutions/lifecycle and
placement, dimensional pre-lookup admission, changed trust, ignored completion
writes and withdrawn proof records, original legacy predecessor/current-writer
checks, substituted quorum-valid headers and directory predecessor replay.
Real signed genesis/events/transcripts qualify complete directory history and
quorum successors after retirement/forget/re-add, missing old incarnations,
later quorum-certified forks, replay debt and original identity across format
nine/ten predecessors in both directions. Frozen qualification passes 191 core,
360 ordinary Store, 35 paged Node, the certified-writer migration entry point
and provisioned Btrfs native capture/recovery: 588 distinct cases. The ordinary
suites leave 26 Store and one Node case ignored; that native case runs separately
on disposable Btrfs with a logical sparse 1 TiB file. Formatting, strict locked
workspace/all-targets Clippy, all-target test compilation and four debug program
builds pass under Cargo/rustc 1.99.0. Frozen source, seven binaries and 22 embedded
protocol/helper inputs match. Native mount/loop/image cleanup is independently
checked. Logs, manifests and the distinct inventory are retained in
`/tmp/mb-m6-directory-certification-validation-6g6tokyt`; the post-commit audit binds
those inputs to the commit. Incremental-cache cleanup reclaims 8.01 GiB,
leaving about 51.4 GiB in `target`, with qualified binary hashes
unchanged. Other ordinary/native suites and installed artifacts were not rerun.

This completes the staged public directory proof through current coding,
original-history transition and quorum binding. Full metadata/physical policy,
guarded public/private checkpoint ownership, payload custody, normal paged
capture/retention/seed recovery and deferred dense capacity/native platform
qualification remain open. R3-SINGLE-OWNER-METADATA and Milestone 6 remain open.

## Guarded directory checkpoint custody (2026-10-10)

The format-ten quorum proof now enters the original guarded custody operations.
The retention descriptor keeps its exact directory header, certificate hash,
independent event-trust hash and cumulative transition work. Default generic
headers preserve original descriptor bytes and APIs. The directory owner uses
separate version-one journal/certificate/dependency namespaces and pin prefix
six; original namespaces and prefixes remain unchanged. UUIDs cannot be reused
across the two checkpoint layouts, including cancelled owners, because original
private/payload backlinks share owner IDs.

Acquisition requires the completed original-history transition, exact bound
quorum, independent event trust and actual current predecessor. It pins all
three public roots in one short writer, then each nested original legacy/signed
source root, source/descriptor part and coding forest before evidence I/O.
Every local typed stream must reach EOF before publication. All pin/publication
writers recheck trust and the current head; traversal holds no production writer.
Interrupted building owners replay only the exact descriptor and proof.
Published owners recheck their complete original closure. Cancellation fences
IDs permanently, and each release transfers at most one payload, private
revision dependency or public root. Current checkpoints cannot be cancelled or
released. Certificate readback/deletion remains exact and atomic with the final
public root.

Private revision and actual READY information/parity custody share the same
checked code for both layouts. The common budget includes transition/replay,
public traversal, private bootstrap/pages and each physical role's original
coding-witness replay. Acquisition orders cannot reset debt. Readback and volume
retirement locate the actual UUID-unique checkpoint layout under the same control
snapshot/writer. Node adapters independently read original event authority,
authenticate local encrypted private metadata, enforce local ownership and
verify the full READY bytes against the original coding commitment.

New Store cases qualify transitive ownership through capture retirement,
shared owners and reopen; exact interrupted replay and changed retry; current
successor fencing; external-only authority refusal and missing part EOF;
ignored initial/nested pin and certificate writes; changed final trust;
corrupt/oversized certificates and ignored final retirement; cross-layout UUID
exclusion; shared private/bootstrap/native anchors and physical information/
parity custody; and shared budget exhaustion in both acquisition orders. New
Node cases qualify authenticated private custody with poisoned flat-state
cache, plus real information and parity forget/rollback/reopen and destructive
volume guards through the original runtime scenarios.

Frozen qualification passes 191 Core, 369 ordinary Store and 38 paged Node
cases, certified-writer migration and provisioned Btrfs capture/recovery: 600
distinct cases. Original legacy information upgrade passes in the Node suite
and an independent repeat. Twelve new cases cover directory ownership and
local custody. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and four debug program builds
pass. Frozen Rust/Cargo source, seven binaries and 22 embedded protocol/helper
inputs match; native mount/loop/image cleanup is verified. Evidence is retained
in `/tmp/mb-m6-directory-custody-validation-i67_41gh`; the post-commit audit
binds the inputs to the commit.
Cache cleanup reclaims 10.07 GiB, leaving about 51.5 GiB in
`target`, with qualified binaries unchanged.
The ordinary suites leave 26 Store and one paged Node case ignored. The native
case runs separately on disposable Btrfs using a logical sparse 1 TiB file,
without qualifying dense retained capacity. Other ordinary/native suites and
installed artifacts were not rerun.

This stages custody and individual local roles. Complete distributed readiness,
atomic checkpoint activation, enclosing metadata/physical policy including SQL/
WAL/scratch headroom, normal paged producers/retention/seed recovery and deferred
dense capacity/native platform gates remain required. R3-SINGLE-OWNER-METADATA
and Milestone 6 remain open.

## Admit checkpoint custody before validation (2026-10-10)

Checkpoint custody now admits prospective private and physical dependency
work before authenticating their complete bytes. A read snapshot subtracts
original proof/public, private and other payload debt before original-witness
point replay. Each authenticated page is admitted before fetching and each
framed record before decoding. The publication writer rechecks all current debt
before byte validation and pin/counter publication. Exact same-role retries
reuse their existing charge; they still authenticate the witness and bytes.
Both original and directory layouts use these checks without changing signed
or journal encodings. Tests reject exhausted byte/page/record dimensions,
stop before an over-budget page fetch, reject damaged witness pages through
admission first, reject byte-validation callbacks in both acquisition orders,
and preserve exact-budget private/payload retries and counters.

Frozen qualification passes 192 Core, 369 ordinary Store and 38 paged Node
cases, certified-writer migration and provisioned Btrfs capture/recovery: 601
distinct cases. Formatting, strict locked workspace/all-targets Clippy, all-target
test compilation and four debug program builds pass. Source, seven binaries and
22 embedded inputs match; native mount/loop/image cleanup is verified. Evidence
is retained in `/tmp/mb-m6-custody-admission-validation-6my7zoqc`; a post-commit
audit binds the qualified inputs to the commit.
Removing 68 obsolete hashed workspace executables and incremental
cache reclaims 28.43 GiB, leaving 31.5 GiB in `target`. Current build outputs,
prior qualified paths and all seven qualified binary hashes are preserved.
The ordinary run leaves 26 Store and one paged Node case ignored. The native
case uses a sparse logical 1 TiB file on disposable Btrfs, without qualifying
dense retained capacity. Other ordinary/native suites and installed artifacts
were not rerun. Full distributed readiness/atomic activation, enclosing metadata/
physical policy including SQL/WAL/scratch headroom, normal paged producers and
seed recovery, and the deferred dense capacity/platform gates remain open.

## Linux database directory binding (2026-10-10)

Linux control and parity stores now retain an opened, owned directory
that rejects group/other write access.
A separate SQLCipher Unix VFS keeps the held procfs directory path through
main database, WAL, SHM and journal operations instead of resolving it back to
a replaceable pathname. Live connections to the same directory share a retained
descriptor so the first connection's SHM pathname remains valid after it closes.
Node control-key publication, existing-volume manifest/key opens, saved reader
configurations and scratch allocation-domain accounting use that directory.
Existing-reader opens never create a missing catalog; public volume records keep
their original ordinary paths and signed/schema encodings remain unchanged.

The before-fix test under `/tmp/mb-m6-directory-handoff-negative-ptr1d9yd`
reproduces a saved reader selecting a replacement control database after its
original directory is renamed. The completed Node regression authenticates
original control and READY parity bytes while an independently opened replacement
owner holds different bytes at the old path; reader writes affect only the original,
and the original lock stays exclusive until final reader/configuration release.
Five Store regressions cover reparented WAL readers/writers and first-connection
release, replacement symlinks, invalid/missing database leaves, raw Unix names,
bound scratch accounting and parity publication/reopen.

Frozen debug-source qualification passes 1,325 ordinary workspace/all-targets
cases reported by 19 test drivers and one provisioned Btrfs retained-capture/
recovery case: 1,326 distinct passing cases. The ordinary total includes 63 vendored
library/protocol cases. Ordinary drivers report 121 ignored cases; one runs
separately on Btrfs, leaving 120 unexecuted. Formatting, strict locked
workspace/all-targets Clippy, all-target test compilation and all four debug program
builds pass with the established 8,192-descriptor test limit. All 250 Rust/Cargo
source files, 23 binaries and 22 embedded inputs remain unchanged.
Evidence is retained in `/tmp/mb-m6-directory-binding-validation-guihu189`;
the post-commit audit binds those inputs to the commit.
Native mount/loop/image cleanup is verified. The Btrfs case uses a sparse logical
1 TiB file; dense retained capacity and installed-artifact qualification remain open.
The initial harness assertion on an all-ignored target is retained; continuation
checks its exact zero-pass/ignored inventory and requires positive exact counts for
every ordinary target against the same frozen inputs, without repeating passed builds
or native coverage.

Generated-artifact cleanup removes 5 obsolete hashed
workspace executables and incremental cache, reclaiming 16.42 GiB and leaving
31.5 GiB in `target`. Current build outputs, prior qualified paths and all
23 current binary hashes are preserved.

This closes saved-reader directory redirection on Linux. Atomic source-admission
to writer/leaf/version handoff, initial volume setup, external-owner reconciliation,
complete retained history/payload joins, enclosing metadata/physical quotas and
SQL/WAL/scratch budgets, normal paged producers/retention/seed recovery, the topology/
signature stall and current installed-artifact qualification remain open. Dense
1 TiB and native Windows/macOS qualification remain explicitly deferred by the user;
R1, R2/R3 and Milestone 6 remain open.

## Initial control writer admission (2026-10-10)

Linux startup now captures control-catalog, WAL, rollback-journal and private
key-envelope versions around read-only source admission. Existing SHM mappings
retain identity, length, ownership and permission checks while allowing transient
read marks. The first writable directory opener checks the admitted versions
before native open and immediately afterwards, including SQLite's public
HAS_MOVED check against its opened main inode. These checks precede journal-mode
changes, schema migration and record replay. A disappeared admitted catalog
cannot become a new empty catalog. An absent catalog with orphan journals rejects
before lock creation or permission changes, with a preservation procedure.

Read-only admission also returns the authenticated database key. Interrupted
rekeys open that key directly before completing their existing wrapped target,
without first trying an unverified writable key. Existing legacy catalogs open
before new key publication; fresh random keys remain durable before catalog
creation. Control and parity rekey verification retains the original directory
capability through close and readback. Signed/schema encodings remain unchanged.

The before-fix regression under `/tmp/mb-m6-control-handoff-negative-drha6hip`
confirms startup accepted a valid encrypted withdrawn catalog substituted after
source admission. Its expected failure and frozen source/binary hashes are retained.
The completed Node case preserves exact file bytes and versions after catalog
replacement, disappearance, key replacement and newly appearing WAL input.
Two further Node cases cover orphan WAL/SHM/journal preservation before claiming
ownership, and legacy/wrapped/interrupted key selection and normal startup.
Five Store cases cover fresh/existing admission, changed inputs before writes,
the native opened inode despite matching current pathname versions, private-file
publication without resetting database/journal versions, and directory-bound
rekey verification after replacement.

Frozen debug-source qualification passes 1,333 ordinary workspace/all-targets
cases, including 63 vendored cases, and the provisioned Btrfs retained-capture/
recovery case: 1,334 distinct passing cases. Eight new cases qualify this
increment. Ordinary drivers report 121 ignored cases; one runs separately,
leaving 120 unexecuted. Formatting, strict locked workspace/all-targets
Clippy, all-target test compilation and four debug program builds pass with the
8,192-descriptor test limit. All 250 source/manifest files, 23 binaries and
22 embedded inputs match their frozen hashes. Evidence is retained in
`/tmp/mb-m6-control-handoff-validation-48sfkfhn`; the post-commit audit binds
those inputs to the commit. Native mount/loop/image cleanup is verified.
The native case uses a sparse logical 1 TiB file;
dense retained capacity and installed-artifact qualification remain open.

Cleanup removes 5 obsolete hashed workspace executables and incremental
cache, reclaiming 16.07 GiB and leaving 31.5 GiB in `target`. Current outputs,
prior qualified paths, installed qualification roots and all 23 current
binary hashes are preserved.

This qualifies initial Linux control admission and writable-open handoff.
Complete namespace/leaf lifetime and initial volume handoff, external-owner
reconciliation, complete retained recovery/upgrade policy, enclosing metadata/
physical quotas and SQL/WAL/scratch budgets, normal paged capture/retention/seed
recovery, topology/signature diagnosis and current installed-artifact gates remain
open. Dense 1 TiB and native Windows/macOS qualification remain explicitly deferred;
R1, R2/R3 and Milestone 6 remain open.


## Initial retained-source quota adoption (2026-10-11)

`configure_catalog_retained_source_quota` now accounts for paged data that was
published before source limits were configured. Its initial immediate writer
visits one bounded source binding at a time using the protocol-record primary
key. SQL checks namespace, 32-byte key and record lengths before allocating
row values; an absent initial cursor includes malformed empty first keys.
Every owner must reconcile with the original signed paged descriptor,
publication/root and Verified/Cancelled validation fences, exact original
source facts, recipe/backlink and nonzero physical anchor pin. Existing local
verified facts supply the source join; adoption does not reread payloads or
create new checkpoint authority.

The writer creates one source charge per exact dataset/source identity, with
an owner count spanning published and cancelled bindings. A cancelled owner
remains billed until actual binding cleanup. Each adopted bundle receives a
closed zero-credit Published/Cancelled reservation, supporting the existing
read, cancellation and final-owner cleanup routes without reserving retroactive
credits. New migration can borrow adopted sources at the exact dataset/guild
limit through the existing dependency holds. Original binding formats 1/2/3,
generations, signed roots, recipes, anchor counts and original journals remain
unchanged. Initial policy and all counters commit together; a late invalid row,
exhausted byte/source limit or ignored/aborted accounting write rolls back every
valid prefix. Existing enabled policies still resize only upward without a
history scan, and missing accounting cannot become new zero usage.

Five new Store regressions cover shared and cancelled custody, exact limits,
original binding layouts/generations, read-only/reopen behavior, concurrent
initial activation, independent datasets/guilds, authenticated substitution,
malformed/empty/oversized rows, late orphan owners and SQL faults. The existing
native recovery fixture retains its quota-before-migration case. A second case
enables dataset/guild quotas after real native migration, checks unchanged
bindings, then exercises shared admission, source loss, interrupted replacement,
reopen and exact restoration. Both provisioned Btrfs cases pass in 29.85 and
28.37 seconds, with mount/loop/image cleanup verified.

Frozen debug-source qualification passes 192 Core, 385 ordinary Store, 117
ordinary Git, 38 paged Node, the certified-writer migration entry point and the
two native cases: 735 distinct tests. Formatting, strict locked workspace/
all-targets Clippy, all-target test compilation and four debug builds pass.
Source and eight qualified program/test-driver hashes remain unchanged. The
logs, source/binary manifests, driver and complete passing-case inventory are
retained in `/tmp/mb-m6-source-adoption-validation-7onfqby1`; the post-commit audit
binds the code to the commit. Full Node/CLI suites and installed artifacts were
not rerun; 26 Store and 64 Git cases remain ignored.

Initial adoption performs a complete ownership scan under one writer; its total
SQL/WAL work and headroom still require enclosing policy qualification. It counts
unique non-hole logical data bytes, excluding private/bootstrap metadata,
physical payload/coding, sparse lengths and aliases. Complete enclosing budgets,
normal paged capture/packing/checkpoint/retention/seed consumers and generation
floors remain open. The native fixture uses sparse logical 1 TiB; the user-deferred
dense capacity and native Windows/macOS gates remain separate acceptance work.

## Authenticated retained public checkpoint transport (2026-10-11)

Retained individual and directory candidates can serve their exact original
certificate and one authenticated public page over the existing signed peer
channel. Requests bind layout, owner UUID and original checkpoint hash. The
owner must be Published, and a page must descend from one of its exact retained
public roots with the original dependency and root pin. A short query-only
snapshot checks certificate identity, root ownership and each authenticated
parent edge before fetching the child. A path is bounded to four references;
certificate and page decoders bound allocation to 32 and 64 KiB. File/Git private
plaintext is excluded. Historical-member authorization preserves recovery after
member removal, while unrelated peers cannot read these owners.

The client checks the original certificate against independently supplied
historical trust and the requested checkpoint hash, then authenticates each page
against its exact requested reference. Catalog traversal exposes its bounded
path while preserving leaf order, aggregate EOF accounting and failure fencing.
The new peer variants are appended; existing signed models, persisted owner
records and older wire encodings remain unchanged. The owner UUID is a locator,
not authority to advertise a current/protected checkpoint.

Core fixtures cover branching traversal, maximum depth, bounds and forged/corrupt
paths. Store fixtures use real original-history proofs, shared retained roots,
staging retirement and query-only reopen, rejecting damaged ownership and
certificate records. Real QUIC cases stream all public roots for both layouts,
including a valid signed source tree at maximum depth, after staging retirement,
node reopen and requester removal. They reject outsiders, wrong trust, forged
child paths, private scope, corruption and cancelled owners. The current SQL
head stays absent throughout candidate access.

Frozen qualification passes 194 Core, 386 Store, 117 Git, 530 Node, all remaining ordinary workspace targets and both provisioned Btrfs recovery cases: 1351 distinct passes in 1354 executions. Three transport cases run both in the
preflight and full Node suite. Formatting, strict locked workspace/all-targets
Clippy, all-target test compilation and four debug builds pass. Source and all
23 program/test-driver hashes match. Both native cases use sparse logical
1 TiB and verify resource cleanup; they do not qualify dense capacity. A harness
accounting error on an ignored-only target was corrected and the remaining
suites resumed on the same unchanged source and binaries. Logs, both drivers,
source/binary manifests and exact passing/ignored inventories are retained in
`/tmp/mb-m6-page-transport-validation-5k2dmc0s`. 121 other ignored cases remain unexecuted.

This closes retained public transport. Full enclosing resource/metadata/physical
admission, private and distributed payload availability, normal capture/packing/
checkpoint/retention/seed recovery, atomic activation and the remaining installed
artifact matrix remain required. Dense 1 TiB and native Windows/macOS
qualification remain deferred at the user's request.

## Installed recovery and signature-retry qualification (2026-10-11)

The pinned Nix musl release runtime and optional Git alias built from `7d0edb3`
pass the current installed Linux process slice. All 320 tracked source files
match the immutable Nix source copied for this build. The runtime and alias have
separate retained GC roots; older qualified roots remain preserved.

All three isolated-PATH Git packaging scenarios, 23 ordinary process tests,
raw Unix paths, the stock-Git bridge and five-daemon topology/seed recovery pass.
The baseline completes in 812.01 seconds. Two further fresh complete
topology runs partition the relay-only signer after coding-signature dispatch
and abruptly crash the coordinator after four durable signatures. An independent
complete stopped DB/WAL copy verifies all four original signatures, the proposal
lock and bounded original coding transcript. Original catalog/WAL/SHM/key bytes
remain unchanged. Restart resumes the same event and attempt, and the exact
event must install with all five original authentic signers before backup commit.
The runs have different correlated request IDs. No daemon interruption hook is
used. This qualifies one controlled fault scenario twice, not the full fault
matrix or the cause of the historical `3155689` outlier.

There are 27 distinct Rust process cases in 28 positive executions, with the three
packaging scenarios recorded separately. Live daemon identities match the exact
installed static payload. Independent final audits verify all 320 source hashes,
eight wrappers/payloads, the Git alias and two frozen driver hashes, and restored
network/forwarding plus mount/loop/image cleanup. The earlier 1,351-case workspace
result is retained only after verifying identical code inputs and all 23 qualified
binary hashes; those suites were not rerun for this installed slice. Cargo's
package-only driver build temporarily rebound four shared debug launchers. Their
exact original qualified artifacts remained intact in the dependency directory
and were restored before reusing the result; all 19 original test drivers stayed
unchanged. The binding audit records both original and rebuilt artifacts.
Auxiliary uncommitted work and older installed roots remain preserved. Evidence,
exact case inventory, private peer logs and build/qualification/audit drivers are under
`/tmp/mb-m6-installed-7d0edb3-c4pmnqci`. A documentation-only successor records
this evidence; the source and candidate qualified here remain exactly `7d0edb3`.

R5's historical stall diagnosis and complete fault matrix remain open. Mandatory
packaged CI integration is recorded next. R7's remaining native,
upgrade, multi-volume, private-Tor and platform matrix, full enclosing metadata/
resource/physical admission, normal paged producers and seed recovery, and atomic
activation remain required. Dense 1 TiB and native Windows/macOS qualification
remain deferred at the user's request.

## Mandatory installed relay-signature retry gate (2026-10-11)

The packaged process runner now requires the provisioned fault case in its
compiled inventory, then runs it twice after ordinary process, raw-path,
stock-Git and baseline topology/seed recovery. Each fresh run has a 3,000-second
process-group bound and requires exactly one positive test plus one bounded
original-signature proof. The gate checks all stopped-catalog, transcript,
original-input, exact installed-event/five-signer, route restoration and commit
facts. It correlates request/guild/event/group/attempt/sequence/signer identities
to the original coding-add dispatch over RelayFallback and the exact durable
four-signature trace. Malformed, duplicate, missing or incomplete proofs,
non-boolean status fields, invalid identities and repeated request IDs reject.
Network/forwarding resources must match the baseline after each run before the
next starts. Both proofs enter the qualification manifest, and the existing
final source, installed wrapper/payload and driver identity checks remain.

Cargo compiles the workspace/all-target test configuration once, keeping the
previously qualified debug configuration rather than rebinding its launchers
through a separate package-only feature configuration. Every application process
continues to use the complete installed candidate. The existing mandatory
packaged CI job invokes this runner; its build, packaging and diagnostic/cleanup
steps are preserved.

All 11 boundary checks pass, including omitted/false proof facts, malformed and
duplicate records, field/trace substitution, duplicate fresh-attempt evidence,
and a first run leaving network resources. Both actual retained installed fault
records also pass the complete new gate with different request IDs. Formatting,
locked workspace/all-target test compilation, network-script syntax and diff
checks pass; all 23 prior workspace binary hashes,
installed wrappers/payloads/alias and frozen drivers stay unchanged, and auxiliary
uncommitted work is preserved. Evidence and the driver are under
`/tmp/mb-m6-packaged-retry-gate-validation-226p4tp4`.

Fresh exact-source qualification on `d80c108` passes the pinned Nix musl
build, all three isolated-PATH Git packaging scenarios and the complete mandatory
installed runner: 23 ordinary process cases, raw Unix paths, the stock-Git bridge,
five-daemon topology/seed recovery and two fresh relay signer partition and
coordinator crash runs: 27 distinct process cases in 28 positive executions. The
baseline passes in 774.93 seconds; the two interruption runs pass in
711.91 and 742.50 seconds. The runner validates both original-signature
proofs with distinct request IDs and checks network/forwarding cleanup after
each run. Each proof authenticates the original four signatures and transcript
from a separate complete stopped DB/WAL copy, preserves original stopped inputs,
and requires the same event/attempt with all five original signers before backup
commits. Both fresh interruptions occur before activation completes; they do not
add installed coverage of the completed-activation retry branch. All 320 tracked
source files match the immutable Nix source; installed wrappers/payloads/alias
and both frozen test drivers stay unchanged. Independent
live daemon observations identify the installed static payload on all five peers.
The final independent audit verifies source/candidate/driver identities and
network, forwarding, mount, loop and image cleanup. Workspace/all-target driver
compilation preserves all 23 previously qualified workspace binary hashes;
identical Rust/dependency inputs retain the earlier 1,351-case qualification
without rerunning it. Auxiliary uncommitted work and all installed roots are
preserved. Evidence, exact case inventory, private peer logs and independent
audits are retained under `/tmp/mb-m6-installed-d80c108-4hjjpv1t`.

This qualifies the committed mandatory runner against a fresh complete installed
candidate. R5's historical stall and full fault matrix, R7's remaining native/
upgrade/multi-volume/private-Tor/platform matrix, enclosing admission and normal
paged recovery remain open. Dense 1 TiB and native Windows/macOS qualification
remain user-deferred.

## Dataset and guild encoded-page quotas (2026-10-11)

The existing store writer now reserves retained encoded-page bytes, page counts
and open intent slots per dataset and in aggregate across each guild. Guild
charges include every dataset's private/source pages and public guild pages.
Exact reservation replay, staging, publication, cancellation and actual
final-owner GC update all three ledgers atomically. Shared pages are charged
once; cancelled and unpublished pages stay charged until physical collection.

Initial enablement validates one bounded original page/metadata or reservation
row at a time, rejects orphan/inconsistent records and reconciles the exact
original store totals. Existing protocol rows remain unchanged. Persistent scope
and membership markers reject missing accounting; loan identities bind the
original capacity. Later policy resizing is grow-only and scan-free.
Ignored/aborted SQL writes and suppressed metadata deletion reject and roll back
accounting and ownership together.

Eight new Store fixtures cover independent/concurrent scopes, private/public
sharing, adoption, immutable credits, corrupt records and SQL faults. Existing
legacy migration formats 1/3/4/5 now enforce these page limits. Both provisioned
Btrfs native variants pass with limits enabled before migration or adopted
afterward, including shared migration, source loss, interrupted repair and
restore (32.36s and 30.90s). Fresh frozen qualification passes the complete
ordinary workspace/all-target inventory and both native cases: 1,359 distinct
tests in 1,367 positive executions, including 194 Core, 394 Store, 117 Git,
530 Node and all ordinary command/process/vendored targets. Formatting, strict
locked workspace/all-targets Clippy, all-target compilation and four debug
programs pass. All 322 source files and 23 executable paths stay unchanged during
qualification; the documentation-only update follows the run. Native mount/
loop/image cleanup, 29 archived qualification paths with their original inodes,
14 auxiliary uncommitted files and all installed roots are verified. Cache
cleanup reclaims 8.94 GiB, leaving 46.75 GiB in `target`, with qualified artifacts
unchanged. Evidence and exact case inventories are under
`/tmp/mb-m6-scoped-page-quota-validation-on4iksql`.

Other 121 ignored cases remain unexecuted; installed artifacts were not rebuilt
for this change. The native cases use sparse logical 1 TiB, without dense
qualification. These limits account for encoded page blobs; SQL/WAL,
index/record overhead, physical payload, scratch and traversal budgets still
require the enclosing policy. Normal paged capture/checkpoint/retention/seed
production, verified generation-floor retirement and remaining R1/R2/R3/R5/R7
gates stay open. Dense 1 TiB and native Windows/macOS qualification remain
deferred at the user's request.
