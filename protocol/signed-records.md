# Signed Postcard records

`canonical_bytes` is Postcard 1.1 serialization. Struct fields are encoded in
the order below, without field names. Integer and collection lengths use
Postcard's variable-length representation. A `SignedRecord<T>` is ordered as
`signer`, `value`, `signature`; signatures are Ed25519 over
`u32_be(domain_len) || domain || canonical_bytes(value)`.

| Value | Ordered fields | Signing/hash domain |
| --- | --- | --- |
| `Member` | `node_id`, `recovery_public_key`, `failure_domain` | embedded value |
| `GuildInvite` | `format_version`, `guild_id`, `coordinator`, `coordinator_endpoints`, `nonce`, `expires_at_unix_seconds` | `mutualbackup/guild-invite/v1` |
| `GuildGenesis` | `format_version`, `guild_id`, `coordinator`, `members` | `mutualbackup/guild-genesis/v1`; hash derive-key context `mutualbackup guild genesis v1` |
| `QuorumGuildGenesis` | `genesis`, `signatures` | certificate of genesis signatures |
| `UserRevision` | `format_version`, `guild_id`, `protected_root_id`, `cipher_profile`, `revision_id`, `owner`, `writer_epoch`, `writer_public_key`, `writer_signature`, `sequence`, `parent`, `metadata_sectors`, `data_sectors` | stable signature `mutualbackup/user-revision/v3`; writer signature `mutualbackup/writer-revision/v1`; hash derive-key context `mutualbackup user revision body v3` |
| `PagedUserRevision` (migration codec, format 8) | `format_version`, `guild_id`, `protected_root_id`, `cipher_profile`, `revision_id`, `owner`, `writer_epoch`, `writer_public_key`, `writer_signature`, `sequence`, `parent`, `metadata`, `sources` | `mutualbackup/paged-user-revision/v1`; writer signature `mutualbackup/paged-writer-revision/v1`; hash derive-key context `mutualbackup paged user revision body v1` |
| `WriterFence` | `owner`, `epoch`, `public_key` | embedded value; epochs for each owner are contiguous and permanently certified by checkpoints |
| `RevisionTombstone` | `owner`, `protected_root_id`, `through_sequence`, `last_revision_id`, `last_revision_hash`, `retired_at_generation` | embedded retained-prefix high-water mark for one protected-root chain; checkpoint signatures authorize retirement |
| `SectorRef` | `id`, `root`, `logical_len` | embedded value; sector root is BLAKE3 of exact RS-level bytes |
| `CodingGroup` | `id`, `format_version`, `guild_id`, `data_shards`, `parity_shards`, `shard_size`, five ordered `roles` | ID is BLAKE3 of the same fields except `id` |
| `CodingGroupV2` | `id`, `format_version`, `guild_id`, `profile`, ordered `roles` | versions 2–3 share fields; version 3 gives newly encoded full-byte proof groups a distinct ID from compact version-2 groups with identical bytes and placement; compact plans cannot certify version-3 groups; older full-byte proofs for version-2 groups remain replayable |
| `InformationRole` | `owner`, `sector` | embedded value |
| `ParityRole` | `holder`, `row`, `root` | embedded value |
| `CodingAttemptPlan` | version 1: `format_version`, `attempt_id`, `checkpoint_hash`, `membership_epoch`, `geometry`, `delegator`, `coding_coordinator`, `verification_coordinator`, `expires_at_unix_seconds`; versions 2–3 append `information_roots` | `mutualbackup/coding-attempt-plan/v1`; version 2 carries claimed flat roots or authenticated packed Merkle roots; version 3 requires flat roots with full-byte manifest evidence; virtual-zero inputs use the zero sentinel; version 1 retains its byte-exact legacy layout |
| `CodingRootManifest` | version 1: `format_version`, `attempt_id`, `plan_hash`, `group`; versions 2–3 append `information_bytes` | `mutualbackup/coding-root-manifest/v1`; versions 2–3 carry complete encrypted information shards aligned with data roles, with no payload for virtual-zero roles; replay recomputes both roots from each payload; newly emitted version 3 uses CBOR byte strings, while versions 1–2 retain their original CBOR and Postcard layouts |
| `CheckpointAuthority` | `format_version`, `membership_epoch`, `quorum` | embedded version-5 checkpoint authority; the epoch changes with roster, failure-domain, or quorum-policy authorization |
| `PackedCatalog` | `id`, `format_version`, `revision`, `parent`, `profile`, `sectors`; each sector descriptor is ordered as `id`, `sector_index`, `flat_root`, `commitment`, `slots` | embedded in checkpoint version 7; the catalog ID and each sector ID are domain-separated BLAKE3 hashes of their canonical bodies |
| `GuildCheckpoint` | versions 3–4: `format_version`, `guild_id`, `genesis_hash`, `generation`, `parent`, `members`, `writer_fences`, `revision_tombstones`, `revisions`, `coding_groups`; versions 5–6 append `authority`; version 7 appends `authority`, `packing_catalog` | `mutualbackup/guild-checkpoint/v1`; hash is BLAKE3 of canonical bytes; version 6 introduces root-scoped revision/tombstone records and version 7 maps every retained signed sector through authenticated stable slots to packed coding sectors |
| `QuorumCheckpoint` | `checkpoint`, `signatures` | certificate of checkpoint signatures; versions 3–4 require every listed member, while versions 5–7 require their epoch-bound guild quorum |
| `PagedGuildCheckpoint` (draft public header, format 8) | `format_version`, `guild_id`, `genesis_hash`, `generation`, `parent`, `event_sequence`, `event_head`, `authority`, `authority_root`, `authority_records`, `packed_sectors`, `packed_sources`, `coding` | `mutualbackup/paged-guild-checkpoint/v1`; hash derive-key context `mutualbackup paged guild checkpoint body v1`; body/transition and production activation remain separate gates |
| `QuorumPagedCheckpoint` | `checkpoint`, `signatures` | bounded certificate of paged header signatures under independently trusted current membership/quorum; no member roster is learned from the proposal |
| `CatalogCheckpointAuthorityRoot` (staging codec, format 1) | `format_version`, `generation`, `membership_epoch`, `records`, `summary` | authenticated by the paged header; no standalone signature or activation |
| `CatalogLegacyRevisionRef` (format 1) | `format_version`, `guild_id`, `owner`, `protected_root_id`, `revision_id`, `sequence`, `parent`, `writer_epoch`, `writer_public_key`, `revision_hash`, `body` | `body` authenticates the original signed legacy envelope through guild-scoped Checkpoint pages; original owner/writer domains and revision body hash remain unchanged |
| `MemberSignature` | `signer`, `signature` | signature domain belongs to containing certificate |
| `StorageAcknowledgement` | `format_version`, `operation_id`, `guild_id`, `group_id`, `shard_index`, `row`, `root`, `holder` | `mutualbackup/storage-acknowledgement/v1` |
| `EndpointRecord` | `format_version`, `publisher`, `sequence`, `expires_at_unix_seconds`, `endpoints` | `mutualbackup/endpoint-record/v1` |
| `RecoveryLocator` | `format_version`, `subject`, `publisher`, `guild_id`, `checkpoint_hash`, `checkpoint_generation`, `subject_endpoint_sequence_floor`, `endpoints`, `expires_at_unix_seconds` | `mutualbackup/recovery-locator/v1`, then encrypted inside a recovery bundle; the floor is the publisher's greatest durable observation of the subject's endpoint sequence and lets a seed-recovered subject advance beyond expired DHT records |
| `SealedRecoveryRecord` | `format_version`, `ephemeral_public_key`, `nonce`, `ciphertext` | XChaCha20-Poly1305 with `mutualbackup/recovery-record/v1` associated context |
| `RecoveryBundle` | `format_version`, `subject`, `publisher`, `sequence`, `expires_at_unix_seconds`, `key_envelope`, `sealed` | `mutualbackup/recovery-bundle/v1`; format 1 has no envelope and uses the seed-derived recovery key, while format 2 carries the current quorum-authenticated recovery-key envelope and seals the locator to that epoch |
| peer request envelope | format 2: `format_version`, `request_id`, `caller`, `recipient`, `guild_scope`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `request`; coding path observations carry one canonical bounded active-member target list | `mutualbackup/direct-request/v2` |
| peer response envelope | format 2: `format_version`, `request_id`, `recipient`, `request_hash`, `result`; coding path observations carry a fresh ordered direct/relay/Tor availability result for every requested target | `mutualbackup/direct-response/v2` |

The paged migration codec bounds the complete signed revision to 2 KiB and
both signature collections to 64 bytes before peer-controlled allocation.
Both signatures count toward admission before signing. The shared 8 KiB private
bootstrap limit applies in both the core envelope and private descriptor decoder.
`paged-user-revision-v8.postcard.hex` freezes a deterministic 440-byte signed
codec fixture; it does not establish source availability or protection.
`metadata` is one `CatalogSectorRecord` (version, encrypted `SectorRef`, Merkle
commitment); `sources` is the complete typed `CatalogSectorRoot` (record root,
logical bytes). The streamed sources must include the exact metadata record.
The encrypted metadata contains `PagedPrivateMetadata` format 8, ordered as
`format_version`, `native`, optional `git`, bounded to 8 KiB. Private native/Git
page hashes are never placed in the public revision. Owner and writer signatures
authenticate the roots; checkpoint authorization of the writer fence, complete
private/source joins and durable ownership remain separate activation checks.
Flat revision formats 3–5 and withdrawn private formats 6/7 are unchanged.
Normal capture/checkpoint/recovery does not yet activate this migration codec.

Checkpoint authority staging uses the appended public guild page section
`Checkpoint` (Postcard discriminant 5). Authority record variants, in positional
order, are `Member`, `WriterFence`, `Tombstone`, `LegacyRevision`, `PagedRevision`,
`LegacyBinding`, `LegacyAttestation`. Legacy and paged revisions share one
owner/protected-root/sequence/revision-ID order. Other phases are ordered by
member ID, owner/epoch, owner/root, source identity and source identity/signer,
respectively. The bounded local revision cursor uses a fixed 72-byte key with
a big-endian sequence; it agrees with numeric ordering across varint boundaries.

Authority records are bounded to 4 KiB, the root to 1 KiB, members to 256 and
failure-domain strings to 256 UTF-8 bytes. New signed record signature vectors
are bounded to 64 bytes before allocation. The summary fields are ordered as
`members`, `writer_fences`, `tombstones`, `revisions`, `legacy_revisions`,
`legacy_bytes`, `legacy_pages`, `source_bytes`, `source_pages`, `bindings`,
`attestations`. The record stream, fixed root, referenced legacy envelopes and
paged source roots share the existing 16 GiB represented-metadata and one-million
page-occurrence budget. Repeated references count toward traversal work.
`checkpoint-authority-v1.postcard.hex` freezes a deterministic 55-byte root
binding mixed revisions and both legacy evidence variants.

Each legacy envelope keeps its original 32 MiB cap and signed bytes; readers
authenticate all referenced pages before decoding and matching the exact
revision summary. Ordered authority-record EOF does not establish full source
or legacy-body availability. Complete body/source traversal, membership/fence
and tombstone joins, global revision-ID uniqueness, migration evidence quorum,
private joins, durable transitive root ownership, coding and the full
previous-checkpoint transition remain required before production signing or
activation. The draft public header bridge below does not enable a peer
publication path.

Local SQLCipher retention now follows embedded authority references as well as
byte-tree children: an incremental journal pins the control tree, original
legacy envelope trees and signed paged source trees, and publishes local
retention only after typed control/body/source-record EOF. Its cancellation and
one-root cleanup preserve independent capture/checkpoint pins. This journal is
local storage ownership; source payload/native-anchor ownership, current
certificate guards and the protocol authorization joins above remain required.

`CatalogCodingRoot` format one orders `format_version`, `guild_event_sequence`,
`parts`, `summary`. At most four existing public guild Coding record trees share
64 GiB represented bytes (including the fixed descriptor), one million page
occurrences and 64 million records. The root is bounded to 512 bytes; its
summary orders `groups`, `retired_groups`, `information_roles`, `parity_roles`,
`transcript_bytes`, `fragments`. Global group-ID order continues across parts,
and each group remains entirely within one part. Empty forests have no parts.
The enclosing checkpoint must charge all sections under its combined policy.

Coding record variants are append-only: Header (zero) orders `format_version`,
`lifecycle`, `transcript_hash`, `transcript_bytes`; Transcript (one) orders
`offset`, `bytes`. Lifecycle orders the original `group_id`, `added_at_event`,
`retired_at_event`, `retain_through_event`. The header binds the existing plain
BLAKE3 hash of original signed canonical transcript bytes. Exact contiguous
16 KiB fragments carry that unchanged witness, bounded to 600 KiB in total.
Group roles come from its original signed manifest. All nested signatures are
bounded to 64 bytes before allocation; existing role/evidence geometry bounds,
complete typed/raw EOF, exact counters and Verified transcript replay apply.
`coding-evidence-v1.postcard.hex` freezes a 179-byte four-part forest descriptor;
`coding-transcripts-v1.postcard.hex` preserves its four original signed compact
transcripts. Current delegation, membership, source coverage and retained
lifecycle joins, fixed legacy-group migration and the enclosing certificate
remain required before activation. No peer publication version changes here.

Verified local indexes can record one coding group's part/byte range, original
ID and transcript hash during complete traversal. These cursors are local
metadata, not new signed fields or a substitute for full EOF. Range reads
re-authenticate intersecting pages and replay the unchanged original witness.
The combined packing/coding staging proof charges all its streams and descriptor
under one budget and checks active input coverage; its required authorizer still
joins certified guild history and lifecycle authority before activation.

`CatalogCodingDirectoryRoot` format one orders `format_version`,
`guild_event_sequence`, `records`, `summary`, within 512 bytes. The public guild
Coding record stream carries unchanged bounded `CatalogCodingRoot` descriptors.
Its summary orders `forests`, `coding`, `evidence_bytes`, `evidence_pages`, with
the original coding summary nested unchanged. Empty directories contain an
authenticated empty record stream and no forest descriptors. Every referenced
forest retains all existing limits; global group order and complete nested EOF
apply across forests. `coding-directory-v1.postcard.hex` freezes the directory
root for four original compact witnesses stored in four forests.

The directory requires a trusted enclosing byte/page/record budget at decode,
construction and traversal. The root's own claimed work does not authorize that
budget. Accounting includes a fixed 512-byte envelope, directory stream and all
referenced part occurrences; the forest descriptors already inside the stream
are not charged twice. Local completed cursors may include the original part
reference as well as the existing range, without adding signed fields. A local
retention journal pins logical forest roots before witness traversal and
publishes only after replayed globally ordered EOF. This owns public metadata;
enclosing certified authority/coverage, payload ownership, quotas and checkpoint
activation remain separate required joins. No peer publication version changes.

The directory packing coverage proof carries previously admitted source-authority
bytes, page occurrences and records into the required enclosing budget and
debits both packing streams before traversing coding forests. Record work counts
framed records and bounded signed authority objects, including repeated source
tree occurrences. Its local descriptor reserves one 4096-byte envelope including
the directory root reservation. Original signed/forest layouts remain unchanged;
fixed witness locations belong to the completed disposable index. Durable
composite checkpoint ownership and current certified authority remain required.

The recovery-string vector records whitespace normalization, Argon2id v1.3
parameters and derived identities. Other vector files are hexadecimal raw
Postcard or CBOR unless their extension says JSON.

Paged checkpoint format eight is a separate draft public header, rather than an
extension of the legacy positional checkpoint decoder. Its 4 KiB header binds
the original genesis and previous checkpoint hash, certified event sequence and
head, epoch/quorum, authority root, exact authority record ledger, both packing
roots and coding directory. The authority ledger includes control frames,
separately decoded legacy envelopes, flat legacy source entries and every nested
paged-source frame occurrence. Header validation checks its bounds; exact
identity, counts and full body EOF require the completed store proof.
Owner-private plaintext root hashes are absent from the public header.

The certificate reserves 32 KiB, with at most 256 strictly ordered distinct
active-member signatures of exactly 64 bytes. List and nested signature limits
apply before allocation. Its signing domain and body-hash derive-key context
are distinct from all legacy checkpoints; collecting a different quorum subset
does not change the checkpoint hash. Verification requires an independently
trusted event roster/quorum, genesis and previous checkpoint identity. It never
learns trust from the proposed authority root. Generation one requires no
parent; later generations require the exact trusted predecessor and increment.

One separately supplied trusted byte/page/record budget charges the fixed
certificate envelope plus every logical public closure occurrence. Embedded
root/local descriptor reservations are not charged twice. Existing per-tree,
authority and packing aggregate limits remain; directory forest boundaries
cannot reset the budget. Private/payload work and retained quotas still need
the enclosing policy. `paged-checkpoint-v1.postcard.hex` freezes the new header
and ordered quorum signature layout; it is a header codec fixture, not evidence
of a complete body/coverage or state-transition validation.

The store bridge signs and binds only a completed current-coverage public proof
with exact certified-current variable coding state and a completed authority
successor comparison. It compares exact member records and roots/ledger, and
rereads independent event and previous-checkpoint
snapshots before and after the operation. The private wrapper preserves the
original certificate, transition and indexed body; a raw header, manifest or
body proof cannot create it. These draft APIs do not authorize production
activation: the full retention/quota policy, original coding lifecycle
and fixed legacy-group migration, private/bootstrap/native joins, payload
custody, durable transitive ownership and an atomic current-state publication
or retirement guard remain mandatory. No normal producer, peer version or
seed-only consumer is enabled by this header.

`CatalogCheckpointCodingStateIndex` requires a separately trusted consistent
certified event snapshot, with complete retained and retired variable-group
counts. Fixed trusted point facts bind every original group ID/profile, original
signed transcript hash and exact add/retire/retention events. Their reader must
verify original delegation, historical membership/domains and bound add evidence
(including verified legacy add bindings); a proposal is never that authority.
The directory retains unrelated and retired groups until certified forgetting.
Every packed-sector coverage row must resolve to an active group with current
placement under the same snapshot. Exact group/sector EOFs and a final snapshot
recheck precede the private completion marker. No production writer is held.
The whole public input and conservative fixed row/member/marker work share a
required trusted byte/page/record budget, carried into the authority successor.
Point reads use already verified indexed facts; history ingestion/replay needs
its own enclosing admission before this phase, without resetting that debt.
Internal joins check completion around the full scan without rereading large
descriptors per point. A raw directory proof cannot proceed directly to signing.
This proves the supplied certified variable state; the production bounded
history reader, fixed legacy-group migration, complete coding transitions and
the remaining enclosing publication/ownership gates are still required.

The authority successor comparison preserves every previous historical fence
and every retained original signed revision unless an exact monotone tombstone
retires its prefix. A new/advanced floor must identify a revision present in the
trusted predecessor, with its original ID/body hash and this successor's
generation. Unchanged floors are immutable. New revisions cannot reuse IDs
reserved by the predecessor's retained revisions or last-retired tombstones;
they require active membership and the independently certified latest nonrevoked
writer key. Successor fence advances must be one step and have a new revision;
initial checkpoints may admit their certified contiguous fence history. Removed
owners and revoked historical keys can retain unchanged authorized history.

`CatalogCheckpointTransitionIndex` is constructed only after that complete join
in the existing encrypted scratch store. A required separate job budget admits
both complete public inputs and a conservative bound on indexed comparison
rows; neither input resets the debt. Legacy input keeps its original 32 MiB
certificate bound and signed bytes, with a separately supplied certified epoch/
event witness for formats without authority. Paged input requires a completed
quorum-bound predecessor, whose hash must match independently trusted state.
Original envelope hashes are computed with bounded streaming Postcard hashing,
avoiding another encoded copy. Physical legacy-body references are excluded from
signed identity equality so repagination cannot rewrite signed authority.
Checkpoint rosters allow certified shared failure domains; each coding group's
placement still requires its original distinct-domain checks.
