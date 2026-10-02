# Git-compatible local history and stock Git interoperability

`mutualgit` keeps its index, branches, commits, and worktree state in the
app-owned `.mutualbackup` catalog. File bytes live in immutable native anchors;
the repository does not keep a second `.git/objects` payload store. The daemon
must be running and unlocked for its commands.
Each enrolled root records a versioned local source backend and the mount that
passed its capture probe. After a remount, the daemon repeats that probe before
using the root; an unavailable backend leaves the root unavailable. A root
restored through recovery records this binding on its first successful probe.
New Git adds select a capture plan through that binding. An interrupted add
replays its recorded plan, so a backend change cannot reinterpret its bytes.
Fetched and pushed Git blobs likewise select a native import plan through the
binding; an interrupted import replays its recorded plan. Automatic content
merges use the same backend for their generated raw bytes.
Checkout and restore publish regular files through the selected backend after
the root probe, including when the daemon replays an interrupted checkout.

```sh
mutualgit init /absolute/path/to/source
mutualgit -C /absolute/path/to/source add file
mutualgit -C /absolute/path/to/source commit -m 'first'
mutualgit -C /absolute/path/to/source status
```

The command can also be invoked as `git` by explicitly selecting the optional
alias package. It links to the same `mutualgit` binary and does not create a
Git payload store:

```sh
nix build --no-substitute .#git-command
./result/bin/git -C /absolute/path/to/source status
```

For a Cargo build, a symlink named `git` to the locally built `mutualgit`
binary works the same way. Put that symlink on `PATH` only in shells where you
want the documented MutualBackup command subset; unsupported Git commands fail
explicitly. Keep stock Git later on `PATH`: packed-object import and export use
its raw `cat-file` stream, and the daemon skips the `mutualgit` alias when
selecting it. Use stock Git separately for the bridge examples below.

The local binary supports branches, linked worktrees, exact-byte checkout,
merge, staged reset, hard reset, worktree restore, diff, log, explicit commit pins,
and prune.
`mutualgit rm PATH` removes a clean tracked file or symlink and stages its
deletion. It rejects staged or working-tree changes, and replays an interrupted
unlink before clearing the index. `mutualgit rm --cached PATH` keeps the working
file.
`mutualgit worktree list` reports the current branch of each ready worktree;
an interrupted addition reports its reserved target branch.
`mutualgit worktree remove WORKTREE_ID` removes a clean linked worktree's
tracked files and directory, then releases its branch ownership and index pins.
It refuses modified or untracked content, including an unexpected `.git`
directory. An interrupted removal remains visible as `Removing`; rerun the same
command to finish it after resolving any conflicting file or directory.
After deliberately removing a linked worktree directory, run
`mutualgit worktree prune WORKTREE_ID` from any remaining worktree to release
its branch ownership and index pins. The command refuses an existing path,
staged differences, or an unfinished add or checkout. Use `--force` to discard
staged changes, pending adds, and that worktree's unresolved merge session after
removing the directory. `--force` can also discard an
interrupted initial checkout and its private staging directory after that
worktree directory is gone; later checkouts still block it.
An interrupted registration that has not started checkout can be pruned without
`--force` after its directory is removed.
All `mutualgit worktree` subcommands can be invoked from a linked worktree;
they operate on the shared repository rather than assuming the primary worktree.
It only forgets that worktree's local metadata; its branch and shared commits
remain available. Run the separate history `prune` (or `gc`) command to reclaim
anchors that no remaining ref or index needs.
History prune reports removed logical anchor bytes and leaves physical bytes
unknown when shared extents prevent an exact live accounting. The provisioned
Linux Git gate measures Btrfs shared extents through stage and checkout and
measures unique extents removed after pruning an unreferenced branch.
`mutualgit restore PATH` restores working files from the staged index without
moving HEAD or changing that index; `mutualgit restore --staged PATH` resets
the selected index paths from HEAD without changing working files. Use both
flags to restore the selected index and working paths from HEAD in one
replayable daemon operation. It publishes working paths before the index
transition, so a failed worktree preflight leaves staged bytes intact. Restore
replays an interrupted file replacement when the daemon reopens the repository.
Its durable intent records the old working file's native content root and
length. A pending restore written by an older version without that root
stops before further deletion or replacement and needs operator-assisted
resolution.
`mutualgit reset --hard` restores all tracked working paths and publishes the
matching HEAD index in one replayable transition. It leaves HEAD and untracked
paths alone, and refuses to replace a directory containing untracked files.
`mutualgit tag` lists, creates, and deletes lightweight commit tags. Use
`mutualgit tag -a -m 'release notes' NAME [START-POINT]` to create an annotated
commit tag with the configured committer identity. Both tag forms are included
in encrypted history backups and keep their commits reachable until removed
and pruned. Stock Git can fetch and push either tag form through the remote
helper. Native `mutualgit push` can send a tag to an existing local bare Git
repository with `mutualgit push /path/to/bare.git refs/tags/release`. Native
branch pushes also accept `mutualgit push /path/to/bare.git topic:review/topic`
or full `refs/heads/` names; they can send a branch that is not checked out.
The destination branch must be new or advance by fast-forward. Native
push from a linked worktree uses that worktree's selected branch when no
refspec is given; explicit branch and tag refspecs use the shared history.
`mutualgit fetch /path/to/git-repository` imports branches and tags together;
`mutualgit pull` fetches those refs before merging the selected branch. An
existing local tag may be fetched again at the same object ID, but a remote
rewrite or tag namespace conflict rejects the entire fetch without moving any
refs.
From a linked worktree, `pull` and `merge` use its selected branch, index, and
working files. A conflict session stays with that worktree; resolve paths with
`add`, then use `merge --continue` or `merge --abort` there. The provisioned
linked merge and replay gate remains open in `TODO.md`.
Repository-wide `fetch`, `pin`, `unpin`, `pins`, and history `prune`/`gc` also
work when invoked from a linked worktree; they use the shared repository catalog.
`mutualgit --help` gives the current command forms. Staging, checkout, merge,
and import keep raw file bytes; Git line-ending rules, content filters,
`ident`, and working-tree encodings are inert in this binary. A
`.gitattributes` file remains ordinary tracked data, including when it asks
stock Git to transform files. `mutualgit status` reports the raw-byte policy.
Stock Git may still convert its own working-tree files after exchanging blobs.

Install `git-remote-mutualbackup` on `PATH` to fetch from or push to this history
with stock Git. The URL after `mutualbackup::` is the absolute path to the
MutualBackup source root, not its `.mutualbackup` directory:

```sh
git clone 'mutualbackup::/absolute/path/to/source' local-clone
git -C another-repo fetch 'mutualbackup::/absolute/path/to/source' \
  refs/heads/main:refs/remotes/mutualbackup/main
git -C another-repo fetch 'mutualbackup::/absolute/path/to/source' \
  refs/tags/release:refs/tags/release
git -C another-repo push 'mutualbackup::/absolute/path/to/source' \
  refs/heads/topic:refs/heads/topic
git -C another-repo push 'mutualbackup::/absolute/path/to/source' \
  refs/tags/release:refs/tags/release
```

The helper uses the same default local control socket as `mutualgit`. Set
`MUTUALBACKUP_CONTROL_SOCKET=/path/to/socket` if the daemon uses another one.
It streams verified native blob anchors into **stock Git's own** object
database on fetch and imports raw stock Git blobs into native anchors on push.
The MutualBackup repository keeps no Git payload mirror. Stock Git owns its
exported object copies; its checkout or staging may apply that client's
attributes or configuration outside our control. The exchanged Git blobs retain
their raw object IDs and bytes. Push accepts a new or fast-forward branch only
when that branch is not checked out in a MutualBackup worktree; force pushes and
branch deletion are unsupported. `mutualgit fetch` and `mutualgit pull` accept
existing local bare or working-tree Git repositories; `mutualgit push` targets
local bare Git repositories. Tag pushes create new tag refs after their complete
object graph is durable; moving, deleting, and force pushing tags are
unsupported.
