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
Neither mode downloads missing sectors; recovery beyond the preserved local
inputs is still required for the complete R1 procedure.

Create the destination's parent outside the revision and ciphertext input
directories, then run:

```sh
mutualbackup legacy-export \
  --revision-file /preserved/inputs/revision.postcard \
  --sectors-dir /preserved/inputs/ciphertexts \
  --destination /exports/revision-001 \
  --seed-file /preserved/recovery.txt
```

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
recorded hash. For historical fixed 3+2 groups, any three valid cached positions
can recover the codeword; every reconstructed shard root and the coding relation
are checked. Zero-length filler positions are inferred only when their certified
full-sector root authenticates all-zero bytes. Cache rows from another checkpoint,
guild or group cannot serve as reconstruction inputs.

For packed checkpoints, cached `packed-sector` records supply one authenticated
payload at a time. Descriptor identity, guild, roots/commitments and source chunk
hashes are checked; chunks from multiple packed sectors join into the exact
64 KiB ciphertext referenced by the signed revision. Missing, oversized or corrupt
records fail without publishing an export. The reader caches one certified
checkpoint and one decoded fixed codeword, and reads one packed payload at a time, rather than an
installation-wide payload map. It can try another certified checkpoint containing
the exact same signed revision if the first cannot reconstruct a sector.
This does not download peer data or reconstruct variable-profile parity from
original parity volumes. Keep those volumes, coding transcripts and peer-held
history for the remaining recovery procedure.

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
