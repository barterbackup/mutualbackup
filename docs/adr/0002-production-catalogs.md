# Bounded authenticated catalogs for the 1 TiB release target

Status: page foundation and local ownership implemented; production admission
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
uses SQLCipher; private remote addressing/encryption and public authority checks
still need implementation. Cancelled intent records remain as small fencing
tombstones until an authenticated generation-floor mechanism can retire them.
Quota/headroom reservation, record codecs, incremental updates and integration
with capture, packing, checkpoint replay, retention and seed-only recovery
remain open. Local ownership alone does not enable the 1 TiB target.
