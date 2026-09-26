# Protocol contracts

These files describe the current draft protocol. They prevent accidental drift;
they are not a compatibility promise before the release-candidate milestone.

- `local-control.cddl` is the JSON data model on the same-UID Unix socket. Each
  message is prefixed by a 32-bit big-endian byte length and is limited to 1 MiB.
  Clients choose a nonzero 16-byte request ID; responses echo it.
- `peer.cddl` is the CBOR data model carried by libp2p request-response protocol
  `/mutualbackup/peer/2`. Requests and responses are Ed25519 `SignedRecord`s,
  correlate request ID plus request hash, and use the signing domains listed in
  `signed-records.md`. The application frame limit is 600 KiB.
- `signed-records.md` fixes the ordered Postcard fields used for hashes and
  signatures. Postcard is positional, so field order is part of the encoding.
- `vectors/` contains byte-exact valid fixtures and deliberately invalid schema
  fixtures. Rust tests validate the JSON/CBOR fixtures against CDDL and decode
  and re-encode every valid wire fixture.

Serde names are wire names. Structs are string-keyed maps in JSON/CBOR; enums
use Serde's externally tagged representation. Fixed Rust byte arrays are JSON
or CBOR arrays of unsigned bytes. UUIDs are lowercase hyphenated strings in
JSON and 16-byte CBOR byte strings. `Vec<u8>` remains an array of unsigned bytes.

At receipt, schema shape is only the first gate. The implementation also checks
format version, nonzero/correlated request IDs, signer/transport identity,
recipient and guild scope, request hash, freshness, authorization, frame and
queue limits, and object-specific semantic bounds. Errors are capped at 4096
UTF-8 bytes and carry a stable code plus a retryable flag.

`RetireCodingAttempt` is a mutation addressed to the signed plan's delegator
by its assigned coding coordinator. The delegator checks historical plan
authority and arbitrates against accepted verifier evidence under its writer
lock. `CodingAttemptRetired { retired: true }` acknowledges a durable fence for
that immutable plan; later verifier submissions are rejected and holder cleanup
may proceed. A false response leaves accepted evidence in charge of activation,
so the coordinator must not discard the attempt's shards. Request failure or
timeout never authorizes cleanup. Stale launch recovery makes the same decision
locally at its delegator. This adds draft peer message variants without changing
any existing signed-record fields or persisted job encodings.

`GetCodingAttemptRetirement` lets the assigned coder query its delegator about
that exact historical signed plan without creating a fence. Its authenticated
`CodingAttemptRetired` response is true only for an existing matching durable
retirement. A false response leaves delivery retryable. Following rejected
result delivery, a true response allows the coder to resume holder cleanup and
finish its durable submission job; transport errors never authorize deletion.
