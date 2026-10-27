# Explicit native storage enrollment (Linux)

Native SQL catalogs carry authenticated, immutable file ceilings and ownership.
Choose these policies before creating the catalogs. The commands below expose
fresh creation and interrupted creation resume; existing legacy databases,
copied native roots and restored catalogs still require a separate quiescent
adoption/recovery procedure. They are refused by these commands.

Copy and edit [the node policy](examples/native-node-policy.json) and
[the additional-volume policy](examples/native-volume-policy.json). These small
examples use 16 MiB main files and 8 MiB parity budgets for local evaluation.
They do not set the dataset/history capacity or supply the enclosing SQL,
scratch and payload reservations needed for normal paged production. That
integration remains unfinished, and normal paged producers remain disabled.

Policy files are regular JSON files of at most 16 KiB. Every field is required;
unknown fields are rejected. Each database has its own nonzero 16-byte
`policy_id`, version, main/journal/shared-memory/temporary file limits, combined
`total_bytes`, filesystem `headroom_bytes` and `files` ceiling. Size limits use bytes
in multiples of 65,536. `parity_budget_bytes` must exceed parity headroom and fit
the main-file ceiling. Retain the original file for retries: changing the ID,
any ceiling or the original creation budget is refused rather than changing an
existing catalog's policy. Managed rekey and policy migration are separate work.

Before committing a native WAL transaction, the runtime allocates and syncs the
future main-file data extent within the original main and combined ceilings.
This backing remains available when readers delay checkpointing, so allocated
main-file space can exceed its current logical length. A transaction whose
resulting database exceeds the main ceiling is refused even when its WAL fits.
Checkpoint contention can return SQLite's normal busy error; retry after the
checkpoint completes. These checks apply to new commits and do not adopt old
unfunded WAL debt or replace the enclosing resource reservation policy.

Linux disposable scratch budgets cover rounded data reservations and reported
allocated blocks across every database and journal in the job. This includes
ext4 extent-tree blocks, which can grow during allocation or writes. The runtime
checks block usage after allocation, writes and syncs. An operation
that exceeds its budget fails and releases only unused reservations beyond EOF;
visible bytes remain available for rollback. Any excess that cannot be reclaimed
remains charged until truncation or close.
Headroom refusals remain pending across retries until space can be revalidated
or the file releases all its blocks. This accounting does not physically
fund unreported filesystem metadata or the complete scratch ceiling when a job
is declared; that shared admission contract remains unfinished.

Initialize the public identity and keep its recovery string outside the data
directory, then create native catalogs while the daemon is stopped:

```sh
mutualbackup init --data-dir /srv/backup/state --seed-file /srv/backup/recovery.seed
mutualbackup init-native --data-dir /srv/backup/state \
  --seed-file /srv/backup/recovery.seed --policy /srv/backup/node-policy.json
```

`init-native` requires the original initialized identity. It takes the normal
exclusive node lock and can resume its own interrupted creation with the same
identity and policy. Ordinary daemon startup then opens the authenticated native
catalogs. Configure logical parity placement within the selected native ceilings;
the daemon's legacy 10 GiB default does not fit the small example policy:

```toml
data_dir = "/srv/backup/state"
seed_file = "/srv/backup/recovery.seed"
parity_budget_bytes = 8388608
parity_headroom_bytes = 65536
parity_volumes = ["/srv/backup/state"]
```

Create an additional volume in an existing empty directory while the daemon is
unlocked. Keep the policy file outside that directory:

```sh
mkdir /srv/backup/parity-extra
mutualbackup storage create-native /srv/backup/parity-extra \
  --policy /srv/backup/volume-policy.json
```

The daemon validates ownership and policy, durably creates the original identity,
and commits the checked registry entry before making the volume available. A
retry returns the same UUID and retains later budgets and any retired state.
`storage list` shows its state; creating an existing retired volume does not
reactivate it.

Add both paths to the human-owned daemon configuration before restarting:

```toml
parity_volumes = ["/srv/backup/state", "/srv/backup/parity-extra"]
```

Creation does not rewrite that configuration. Omitting a previously registered
volume on restart leaves it visibly offline. Keep the configured logical budget
and headroom within each volume's original native policy. Existing `storage
drain`, `migrate`, `reactivate` and `reconcile` commands retain their normal
durability and retirement rules.
