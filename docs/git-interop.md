# Git-compatible local history and stock Git fetch

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
`mutualgit --help` gives the current command forms. Staging and checkout do
not apply Git line-ending rules or content filters. A transforming
`.gitattributes` rule is rejected before publishing staged bytes.

Install `git-remote-mutualbackup` on `PATH` to fetch this history into a stock
Git repository. The URL after `mutualbackup::` is the absolute path to the
MutualBackup source root, not its `.mutualbackup` directory:

```sh
git clone 'mutualbackup::/absolute/path/to/source' local-clone
git -C another-repo fetch 'mutualbackup::/absolute/path/to/source' \
  refs/heads/main:refs/remotes/mutualbackup/main
```

The helper uses the same default local control socket as `mutualgit`. Set
`MUTUALBACKUP_CONTROL_SOCKET=/path/to/socket` if the daemon uses another one.
It streams verified native blob anchors into **stock Git's own** object
database and leaves the MutualBackup repository without a Git payload mirror.
Stock Git then owns those exported object copies. Its checkout may apply that
client's attributes or configuration; the fetched Git blobs retain their raw
object IDs and bytes. The remote helper currently advertises fetch only;
stock Git push through this URL remains milestone 6 work. For now,
`mutualgit push` and `mutualgit fetch` interoperate with existing local bare
Git repositories.
