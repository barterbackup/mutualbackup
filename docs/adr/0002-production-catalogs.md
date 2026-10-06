# Bounded authenticated catalogs for the 1 TiB release target

Status: page/record framing, typed source records, paged Git container and legacy adapter, local ownership and address/encryption primitives implemented; production admission
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
that problem: local graph admission and backup descriptor bounds differ.

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
summary counts rather than the corresponding flat collections. Their exact
format numbers will be assigned when the consumers are implemented; withdrawn
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
