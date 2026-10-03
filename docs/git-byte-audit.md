# Git byte-path audit (Milestone 6)

The supported `mutualgit` commands preserve file content as raw bytes. The
frontend does not invoke Git's index, worktree checkout, attribute, or filter
APIs. Its libgit2 calls operate on pinned files, in-memory buffers, or Git
objects. An ordinary Git peer may already have converted its working file;
its stored blob is the authoritative input at this boundary.

| Command | Bytes read and hashed/stored | Bytes written or exchanged |
| --- | --- | --- |
| `init` | No payload read. Probes the reflink source backend. | No payload written. |
| `add` | `stage.rs` captures a pinned reflink, then `blob_oid_from_anchor` hashes that descriptor with `git2::Oid::hash_file`. For a symlink it reads the target bytes without following it, captures those bytes, and hashes the anchor. | Writes only the native immutable anchor and index/object mapping. `add --abort-pending` discards an intent and its unreferenced anchor. |
| `rm` | `rm.rs` verifies the tracked path against its raw indexed blob before removal. `rm --cached` only changes the index. | Unlinks the verified working path when requested; no file content is generated. |
| `status` | `status.rs` reads pinned worktree files or symlink targets and compares their raw BLAKE3 hash and mode to the verified staged anchor. Committed trees are decoded from Git metadata objects. | No payload written. |
| `diff` | `diff.rs` reads verified anchor and pinned worktree bytes. It passes raw buffers to `git2::Patch::from_buffers`; that API receives no repository, index, or attributes. | Emits a bounded patch; it does not modify blobs or the worktree. |
| `commit`, `log`, `branch`, `tag`, `pin`, `unpin`, `pins` | `history.rs` builds or reads Git commit/tree/tag objects from stored OIDs and metadata. It references staged blob OIDs without reopening a working file. | Only metadata and refs change. No payload conversion path exists. |
| `switch`, `checkout`, `restore`, `reset` | `checkout.rs` preflights tracked paths by raw descriptor hash or symlink target hash. The selected blob comes from a verified native anchor. | Regular files are published by `SourceBackendKind::publish_checkout_file` as reflinks; symlinks use the anchor's exact target bytes. Replay does not invoke Git checkout or filters. |
| `worktree add`, `resume`, `remove`, `prune`, `list` | Add/resume use the same verified-anchor checkout and raw dirty preflight. Remove/prune verify or retire local worktree state; list reads metadata. | Checkout publishes exact reflinks and symlinks. Removal does not transform retained blobs. |
| `merge` | `merge.rs` supplies verified anchor blobs through `NativeOdb` to `merge_file_from_index`. A content merge creates new bytes by the merge algorithm; the returned bytes are hashed as a raw blob and captured in a native anchor. Conflict resolution stages the user's exact result through `add`. | `checkout.rs` publishes selected or generated anchors. Abort restores exact pre-merge anchors. No renormalization or filter option is passed. |
| `fetch`, `pull` | `fetch.rs` reads Git ODB objects, or streams packed blobs with `git cat-file --batch` (without `--filters`), verifies the object ID, and captures the raw blob stream into native anchors. Pull then uses the same merge/checkout path. | Fetch changes the catalog only; pull writes exact selected/merged anchor bytes. |
| `push` and stock-Git transport bridge | `interop.rs` opens verified native anchors and streams their bytes through a Git ODB writer. Existing packed destination objects are compared with raw `git cat-file --batch`. | Git objects with the same IDs and bytes are written to the ordinary Git repository. A stock client's later worktree conversion is outside this command. |
| `prune`/`gc` | `prune.rs` verifies object-to-anchor mappings and computes reachability from refs, indexes, worktrees, pins, and protected revisions. | Releases only unreachable native anchors/metadata; it does not rewrite surviving blob bytes. |

The CLI declares only these commands and their explicit options in
`cmd/mutualbackup/src/bin/mutualgit.rs`; Clap rejects unsupported options,
including Git filter and renormalization switches. The only production stock
Git subprocess used for payloads is `cat-file --batch`, and its output is
checked against the expected type, length, and object ID. The libgit2 ODB
writer/reader operates on object bytes. No production path calls libgit2's
`add_path`, `checkout_*`, worktree diff, or filter APIs.
`diff` never selects `diff.external` or an attribute's `textconv` driver, and
the native merge takes raw blobs through its built-in merge path rather than
running a configured merge driver. These settings remain inert in the native
repository and at an ordinary-Git object-exchange boundary.

The local Btrfs Git acceptance suite covers mixed line endings, NUL bytes,
symlinks, linked worktrees, merge, restore/reset, stock-Git exchange, and
conversion-inducing config and attributes. This source audit covers the
remaining command mapping; the full milestone gate still requires its exact
source local acceptance and the separate guarded/platform gates in `plan.md`.
