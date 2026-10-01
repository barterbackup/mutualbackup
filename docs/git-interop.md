# Git-compatible local history and stock Git interoperability

`mutualgit` keeps its index, branches, commits, and worktree state in the
app-owned `.mutualbackup` catalog. File bytes live in immutable native anchors;
the repository does not keep a second `.git/objects` payload store. The daemon
must be running and unlocked for its commands.
Each enrolled root records a versioned local source backend and the mount that
passed its capture probe. After a remount, the daemon repeats that probe before
using the root; an unavailable backend leaves the root unavailable. A root
restored through recovery records this binding on its first successful probe.

```sh
mutualgit init /absolute/path/to/source
mutualgit -C /absolute/path/to/source add file
mutualgit -C /absolute/path/to/source commit -m 'first'
mutualgit -C /absolute/path/to/source status
```

The local binary supports branches, linked worktrees, exact-byte checkout,
merge, staged reset, hard reset, worktree restore, diff, log, explicit commit pins,
and prune.
`mutualgit restore PATH` restores working files from the staged index without
moving HEAD or changing that index; `mutualgit restore --staged PATH` resets
the selected index paths from HEAD without changing working files. Use both
flags to reset the index first and then restore those working paths. Restore
replays an interrupted file replacement when the daemon reopens the repository.
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
`mutualgit --help` gives the current command forms. Staging and checkout do
not apply Git line-ending rules or content filters. A transforming
`.gitattributes` rule is rejected before publishing staged bytes.

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
