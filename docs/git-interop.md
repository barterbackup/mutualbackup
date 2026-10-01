# Git-compatible local history and stock Git interoperability

`mutualgit` keeps its index, branches, commits, and worktree state in the
app-owned `.mutualbackup` catalog. File bytes live in immutable native anchors;
the repository does not keep a second `.git/objects` payload store. The daemon
must be running and unlocked for its commands.

```sh
mutualgit init /absolute/path/to/source
mutualgit -C /absolute/path/to/source add file
mutualgit -C /absolute/path/to/source commit -m 'first'
mutualgit -C /absolute/path/to/source status
```

The local binary supports branches, linked worktrees, exact-byte checkout,
merge, staged reset and restore, diff, log, explicit commit pins, and prune.
`mutualgit tag` lists, creates, and deletes lightweight commit tags. Use
`mutualgit tag -a -m 'release notes' NAME [START-POINT]` to create an annotated
commit tag with the configured committer identity. Both tag forms are included
in encrypted history backups and keep their commits reachable until removed
and pruned. Stock Git can fetch and push either tag form through the remote
helper. Native `mutualgit push` can send a tag to an existing local bare Git
repository with `mutualgit push /path/to/bare.git refs/tags/release`; native tag
fetch remains pending.
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
