# Local tuple decoder correction

This is the published cbor4ii 0.3.3 source (MIT), copied from the Cargo registry.
Only `src/serde/de.rs` differs from upstream runtime code. Encoding is unchanged.

The tuple decoder accepts a shorter definite CBOR array than the visitor's
maximum field-count hint, provided the visitor consumes every encoded field.
Versioned MutualBackup coding plans encode nine fields in version one and ten
in versions two/three, while their Postcard-compatible visitor declares ten.
Upstream required the array length to equal that hint before inspecting the
signed version, so version-one transcripts could not pass the peer transport.

Missing required fields still fail in the typed visitor. Arrays longer than the
hint, indefinite arrays and unread trailing fields fail. Fixed-size identities,
signatures and tuples retain exact-length decoding through those checks. The
wire regression covers all three plan versions, signed request/response codec
round trips, unchanged canonical bytes, extra version-one fields, missing
version-two/three roots and short/long fixed arrays. Live packed export exercises
version-one transcripts over the authenticated peer transport.

The crate is excluded from workspace membership; application protocol regressions
exercise the patch. Upstream integration tests and license are preserved.
