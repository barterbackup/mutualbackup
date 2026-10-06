# Guarded backend withdrawal

The FUSE-backed guarded backend is withdrawn. New guarded enrollment commands
are no longer exposed. Old local control requests receive a withdrawal error.
The daemon inspects existing control catalogs read-only before key wrapping,
schema migration, journal replay, or mount recovery. Guarded journals, root
bindings, and pending guarded capture or recovered-anchor intents cause startup
to stop. The read-only check also opens registered Git catalogs when their source
is present and rejects guarded bindings, journals, and root-backed historical
blobs. Root and mount records need not remain for that detection to work.
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
There is no supported automatic migration or offline export tool in this build.
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
4. Historical export and retirement remain blocked pending the verified
   mount-free recovery procedure tracked in R1 of [TODO.md](../TODO.md).
   Preserve the original installation for that procedure; this release cannot
   certify conversion or safe retirement of its protected history.

Fresh native installations continue to use reflink capture. Unsupported source
filesystems are rejected; withdrawal does not introduce a copy or mount fallback.
