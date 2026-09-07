# Source-review TODO

These are high-confidence defects in the implemented Milestone 1 slice. They
are not a list of deferred product features.

## Urgent before Milestone 2

- Enforce the peer frame limit in the actual libp2p CBOR codec. The production
  behaviour uses the dependency defaults (1 MiB requests and 10 MiB responses),
  while the normative protocol and tests claim a 600 KiB application limit.
  Configure both codec bounds explicitly and test rejection on the real path.
- Make the learned endpoint cache replaceable, expiring, and bounded. Each DHT
  refresh currently appends the selected signed addresses to both the swarm and
  Kademlia, but never removes addresses from superseded or expired records; a
  long-lived peer can therefore accumulate stale dial targets without limit.
- Re-arm filesystem watching after a protected root is removed and recreated.
  The callback collapses every event and watcher error to the same dirty hint,
  while `watch_once` has no root-health check that ends the stale watch. After a
  successful reconciliation clears `dirty`, later edits to the replacement
  directory can be missed.
- Remove the blocking `Node` mutex acquisition from relay admission. The relay
  rate-limiter callback runs synchronously while the swarm is being polled, but
  it calls `node.lock()`; source capture and database operations can hold that
  mutex on a blocking worker, pausing all peer networking and relay decisions.

## Correctness and acceptance follow-ups

- Make application byte counters report completed I/O, or rename them to state
  that they count attempts. Outbound requests and responses are added before
  `send_request`/`send_response` succeeds, so a failed or disconnected send is
  currently reported as transferred data.
- Correct the signed-record contract: `protocol/signed-records.md` specifies
  `mutualbackup/storage-ack/v1`, but every signer and verifier uses
  `mutualbackup/storage-acknowledgement/v1`. Add the recovery-locator signing
  domain to the same normative table and make vectors pin both strings.
- Make `root add` perform the complete probe promised by the plan and user docs.
  The current probe checks basic `FICLONE` COW independence only; it does not
  exercise `SEEK_DATA`/`SEEK_HOLE`, verify hole preservation, survive
  rename/unlink, detect a mount-identity change, or reject nested filesystems.
- Close the process-level route evidence gap. The focused test uses real
  libp2p and proves application requests over direct, successful DCUtR, and
  retained-relay paths, but the five-daemon acceptance test only forces the
  direct path. Give its punched and relay-only peers topologies with no
  independently established direct session and assert the reported route plus
  successful backup/restore bytes.
