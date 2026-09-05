# Mutual P2P Backup System --- Detailed Design

## Goal

Build a single Rust binary for mutual backup inside small trusted
communities called **guilds**. A user may belong to several guilds.
Passive servers may join as storage-only participants.

The system should be peer-to-peer, recoverable after total loss of a
user's local disk, tolerant of intermittent connectivity, efficient in
disk/network/CPU usage, usable behind NAT/firewalls, and simple enough
that the user mainly enters or generates a recovery key, joins guilds,
and selects an ordinary folder.

## Terminology

-   **Guild**: a long-lived trusted set of people/nodes. Intended scale
    is a group of friends/acquaintances, potentially up to roughly
    Dunbar-scale.
-   **Host/node**: a machine participating in a guild.
-   **Sector**: the fundamental logical storage unit in the later
    design. Sizes are powers of two.
-   **Information sector**: encrypted primary user data.
-   **Parity sector**: erasure-code parity derived from information
    sectors.
-   **Coding group**: one concrete erasure-code relation among sectors
    on distinct hosts, for example Reed--Solomon `3+2`.
-   **Revision**: an authenticated snapshot of a user's current
    externally relevant state.
-   **User metadata**: private information describing files/directories
    and their mapping to information sectors.

## Local filesystem and UX

The protected source remains an ordinary NTFS/ext4/APFS/etc. folder. The
system should not require FUSE, a custom filesystem, a virtual mounted
disk, or a kernel driver.

The client scans ordinary files and maintains an internal mapping from
protected sectors to local `(file, offset, length)` ranges.

Where useful, the client tries reflinks first so immutable snapshots can
share physical blocks with ordinary files. If reflinks are unavailable,
it may copy while preserving sparse extents and optionally compress
where useful.

Parity is foreign data and must occupy local storage. It can be stored
as ordinary files/objects.

## Identity, recovery, and DHT discovery

The recovery seed must be sufficient to reconstruct the user's
cryptographic identity. There must be no irreplaceable local-only
database.

The DHT is primarily a discovery mechanism. A useful model is an
encrypted **DHT mailbox** associated with the user's public identity.

Recovery flow:

1.  Derive the user's identity from the seed.
2.  Query the deterministic DHT location associated with that identity.
3.  Retrieve records published by guild peers.
4.  Decrypt records addressed to the user.
5.  Learn guild identifiers and current peer/reachability hints.
6.  Connect to guild members.
7.  Obtain authenticated current guild state.
8.  Recover user metadata and data.

Discovery records should be encrypted to the user and signed/versioned.

## Networking

Networking should be independent from storage semantics.

Preferred connectivity:

1.  direct connection;
2.  NAT traversal / hole punching;
3.  relay through a reachable guild member.

Nodes with public addresses can act as rendezvous/relay infrastructure
without becoming privileged storage authorities.

Do not require permanent all-to-all connections. Maintain a small
overlay for gossip/state synchronization and open bulk-data connections
on demand.

### Coding coordinator

Parity generation needs the participating information shards. A
temporary coordinator can be selected based on connectivity, bandwidth,
uptime, and reachability.

Information owners stream encrypted sectors to the coordinator; it
computes parity and forwards parity sectors to their final storage
hosts. The coordinator is an optimization, not an authority.

## Encryption

Primary local files remain plaintext in the user's normal folder.
Backup/network representation is encrypted.

Different guilds can use independent encryption contexts. Since
ciphertext does not need to be persistently stored beside the source
file, encrypting the same source independently for several guilds is
acceptable.

Erasure coding operates over the guild-specific encrypted
representation.

## Mixing different users' data

Mixing users' primary data in one code is intentional.

For systematic `3+2`, three hosts contribute information shards and two
other hosts hold parity shards. Any three of the five reconstruct the
whole codeword.

This lets primary data already resident on guild members' disks serve
directly as data shards instead of requiring each user to replicate all
of their own data elsewhere before adding parity.

### Hard invariant

**A physical failure domain may hold at most one shard from a coding
group.**

Putting two shards of one codeword on one host wastes host-failure
tolerance.

## Erasure coding

Reed--Solomon is currently the leading candidate because it gives
deterministic recovery thresholds, systematic shards, mature
implementations, independent parity rows, and straightforward
verification.

Fountain/Raptor codes, RLNC, and LRC were considered, but RS appears
simpler for this design.

### Extensible parity

A code can conceptually reserve more parity rows than are initially
materialized. For example, define `k` information rows and a large
maximum parity space, while initially calculating only two parity rows.

If another participant later needs a parity shard, calculate another
independent parity row without recomputing existing parity shards.
Unused rows need not be calculated or stored, subject to the limits of
the chosen RS field/construction.

## Temporary outages and adaptive protection

The configured code is a target layout, not necessarily the only
protection that may coexist.

If a normal `3+2` group temporarily loses two hosts, the remaining three
shards still reconstruct the group but have no safety margin. Do not
immediately destroy the old `3+2` layout. The reachable hosts may create
temporary additional protection suitable for the current topology.

If missing hosts return, temporary protection can be garbage-collected.
If the absence becomes persistent, normal background migration can
establish a new optimal layout.

This separates **emergency redundancy restoration** from **long-term
optimization**.

## Guild growth

Growth from five to ten members does not require rewriting every old
group. New members become candidates for new groups, additional parity,
repair, and gradual migration.

Large codes can be storage-efficient, but `k/m` must reflect real
simultaneous availability. A recovery threshold of 90 is useless if only
70--80 machines are normally reachable.

## Fair background scheduler

Work includes:

-   protecting completely unprotected new data;
-   repairing degraded redundancy;
-   creating emergency parity;
-   migrating inefficient layouts;
-   reclaiming deleted data;
-   compacting state;
-   integrity audits;
-   balancing storage and bandwidth.

Do not use strict priorities that can starve maintenance forever. Use
weighted/fair scheduling: unprotected data receives very high weight,
degraded data high weight, cleanup lower weight, and waiting time raises
effective priority.

Where deterministic distributed choices are useful, pseudorandom choices
can be seeded from authenticated shared state plus an epoch/counter.

## Guild state, gossip, and checkpoints

The guild needs authenticated shared state, but not a
cryptocurrency-style blockchain.

A practical model:

-   individually signed events spread through gossip;
-   periodic authenticated checkpoints/snapshots;
-   old history can be compacted;
-   current coding groups are explicit first-class state.

Current layouts should not require replaying all historical events or
rerunning old placement algorithms. Algorithms may propose layouts; once
accepted, the layout itself is recorded.

### FROST/Schnorr

Threshold signatures are attractive for guild membership changes,
checkpoints, and important state transitions. Ordinary events can simply
be signed by their author; threshold-signing every small event would add
unnecessary coordination.

## Atomic transitions

Never destroy old protected state before replacement state is confirmed.

Migration:

1.  Announce/derive desired replacement.
2.  Construct replacement information/parity state.
3.  Distribute it.
4.  Verify it.
5.  Obtain required acknowledgements.
6.  Commit the new authenticated state.
7.  Garbage-collect superseded state later.

The atomic action is the **authenticated state switch**, not
simultaneous deletion on every disk.

## From streams to hierarchical sectors

An earlier design modeled each user's data as append-only virtual byte
streams. Files mapped to stream ranges and coding groups referenced
equal-sized ranges.

That gives compact representation for continuous data but arbitrary
holes make offsets and Merkle maintenance awkward.

The later design is more promising:

> **Make hierarchical sectors the protocol-level storage primitive and
> remove the requirement for permanent flat streams.**

## Hierarchical sectors and Merkle structure

Choose a minimum sector size `B`. Valid sizes are:

`B, 2B, 4B, 8B, ...`

Two adjacent compatible equal-sized sectors can be represented by one
parent sector. This is naturally a binary Merkle hierarchy.

Each sector has a cryptographic hash. Conceptually:

`parent_hash = H(domain || size || left_hash || right_hash)`

Canonical serialization and domain separation must be specified.

Properties:

-   long contiguous regions collapse to one root;
-   parent roots are cheaply computed from child roots;
-   a large sector can be expanded only around an edit/deletion;
-   unaffected subtrees retain their identities;
-   compatible children can later collapse again.

A minimum as small as 64 bytes was discussed. Tiny leaves do not imply
permanently enumerating all leaves because contiguous regions normally
collapse into large parents.

Local Merkle caching should remain an implementation detail. The
protocol needs roots and proofs, not a mandatory cache layout.

## Deletion using hierarchical sectors

Suppose a 1 GiB sector is represented by one root and the owner wants to
remove about 100 MiB from its middle.

1.  Expand the 1 GiB node into two 512 MiB children.
2.  Follow only children intersecting the deletion.
3.  Continue recursively toward useful minimum granularity.
4.  Keep unaffected sibling roots unchanged.
5.  Replace only coding groups covering affected sectors.
6.  Commit replacement protection.
7.  Garbage-collect obsolete information/parity.
8.  Re-coalesce surviving compatible sectors where possible.

This avoids automatically rereading/re-encoding the entire 1 GiB merely
because an interior range disappeared.

## Coding groups over sectors

A coding group operates over equal-sized information sectors.

Example:

``` text
A:data(S)
B:data(S)
C:data(S)
D:parity-0(S)
E:parity-1(S)
```

for `3+2`.

If two adjacent coding groups have identical ordered participants,
roles, code parameters, encryption semantics, and compatible adjacency,
they can potentially be represented as one larger coding group. Their
Merkle roots can be combined upward without rereading underlying bytes.

This is a major mechanism for keeping guild metadata compact.

## Canonical ordering and affinity

Equivalent adjacent groups should strongly prefer the same canonical
participant/role ordering.

If `(A,B,C)` are information roles and `(D,E)` parity roles, randomly
swapping `D` and `E` in adjacent groups gives no useful resilience but
prevents easy coalescing.

General principle:

> **Anything that can be deterministically canonicalized without losing
> resilience should not be randomized or stored redundantly.**

Strong affinity allows many small coding groups to collapse into large
hierarchical groups.

## User file metadata

The guild does not need to know file names or directory semantics.
Private encrypted user metadata maps ordinary filesystem objects to
information sectors.

Conceptually:

``` text
photos/
  a.jpg -> [sector X, sector Y, sector Z, tail_length]
docs/
  report.pdf -> [sector Q, sector R]
```

Metadata may include:

-   relative paths/names;
-   file/directory/symlink type;
-   logical size;
-   ordered sector references;
-   timestamps;
-   permissions/attributes according to policy;
-   sparse extents;
-   metadata schema version.

Metadata itself is protected using the same sector/erasure machinery.

A revision must identify the current metadata root/start so a completely
recovered client can reconstruct the directory tree.

## User revision

The exact encoding remains open, but a revision is a
signed/authenticated description of current user state.

Likely contents:

-   owner identity;
-   revision/version identifier;
-   current metadata root/reference;
-   compact hierarchical representation of current information sectors;
-   parity sectors/objects the host stores for peers;
-   sizes where not implied;
-   Merkle roots;
-   relevant coding-group references;
-   optional previous-revision hash;
-   signature.

A revision should store a large parent root whenever possible rather
than enumerate minimum-sized leaves.

When user data changes, file metadata changes too. They must become
recoverable consistently. A committed revision therefore binds current
metadata state and current information-sector state together.

## Integrity and probabilistic audits

Merkle proofs and erasure-code checks answer different questions.

**Merkle:** "Are these bytes part of the sector committed to by this
root?"

**Erasure code:** "Are these information/parity shards mutually
consistent with the declared codeword?"

Peers can periodically audit a coding group by choosing a pseudorandom
range, requesting bytes plus Merkle proofs, validating the proofs, and
checking the RS relation.

This detects bit rot, stale shards, corruption, and buggy
implementations without continuously rereading every byte. Full scans
can still happen occasionally.

## Garbage collection

Deletion is a request to stop preserving information, not an immediate
destructive command.

**Never physically delete an object while any active/recoverable coding
state still requires it.**

A sector can be reclaimed when the owner no longer references it,
replacement coding groups are committed, no active revision requires the
old object, and any desired rollback/safety grace period has passed.

## Software evolution

Current state must not depend on rerunning a historical placement
algorithm.

Durable records should explicitly version:

-   wire format;
-   metadata schema;
-   hash algorithm/domain;
-   encryption suite;
-   erasure-code scheme/parameters;
-   placement/canonicalization rules where relevant.

Old groups remain interpretable under the version with which they were
created. New software can use new rules for new groups and migrate old
groups gradually.

## Key invariants

1.  One physical failure domain stores at most one shard from a coding
    group.
2.  Old protection remains until replacement protection is committed.
3.  User file semantics remain private; guild state contains only
    coordination information.
4.  Current coding groups are explicit state, not something requiring
    replay of all history.
5.  Transport topology is separate from storage semantics.
6.  Merkle caching is local; roots/proofs are protocol concepts.
7.  Canonical role ordering is used where permutation gives no
    resilience benefit.
8.  Temporary protection may coexist with stable protection.
9.  Background work is fair/weighted rather than strict-priority.
10. Complete recovery must be possible without irreplaceable local
    metadata.

## Open questions

-   Minimum sector size: 64 B, 4 KiB, larger, or adaptive?
-   Exact hierarchical-sector canonicalization rules.
-   Exact RS construction and maximum future parity space.
-   How `k/m` is selected from measured guild availability.
-   Coordinator selection and failover.
-   Exact checkpoint/quorum/FROST policy.
-   Revision serialization and whether revisions form a hash chain.
-   Deletion granularity and when tree expansion is worth its metadata
    cost.
-   Balancing affinity/coalescing against storage balancing.
-   Probabilistic audit frequency and challenge construction.
-   NAT traversal and relay protocol.
-   Guild storage quotas/fairness.
-   Multiple devices per person and explicit failure domains.
-   Membership removal, key rotation, and revocation.
-   Protection against malicious behavior despite social trust.
-   Exact cross-platform metadata required for faithful restore.

## Suggested implementation layers

``` text
UI / daemon
    |
Local filesystem scanner + private metadata builder
    |
Revision + hierarchical-sector model
    |
Guild state + coding-group planner + fair scheduler
    |
Encryption + Reed–Solomon + Merkle verification
    |
Local object/parity storage
    |
P2P transport + NAT traversal + relay
    |
DHT discovery
```

The important architectural principle is to keep these layers
replaceable. DHT discovery, NAT traversal, RS mathematics, filesystem
scanning, local Merkle caching, and guild state evolution should not
become one inseparable protocol.

## Current design direction in one sentence

A trusted guild maintains authenticated explicit coding-group state over
encrypted, Merkle-addressed hierarchical sectors; users keep ordinary
local files, peers jointly create Reed--Solomon parity, networking
dynamically uses direct/NAT-traversed/relayed paths, and all mutations
construct safe replacement state before garbage-collecting the old
state.
