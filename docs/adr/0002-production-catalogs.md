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
Matching live data needs no replacement; lost/damaged data must use the existing
stable-anchor replacement API and cannot acquire an independent Inline lifetime.
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
