# Signed Postcard records

`canonical_bytes` is Postcard 1.1 serialization. Struct fields are encoded in
the order below, without field names. Integer and collection lengths use
Postcard's variable-length representation. A `SignedRecord<T>` is ordered as
`signer`, `value`, `signature`; signatures are Ed25519 over
`u32_be(domain_len) || domain || canonical_bytes(value)`.

| Value | Ordered fields | Signing/hash domain |
| --- | --- | --- |
| `Member` | `node_id`, `recovery_public_key`, `failure_domain` | embedded value |
| `GuildInvite` | `format_version`, `guild_id`, `coordinator`, `coordinator_endpoints`, `nonce`, `expires_at_unix_seconds` | `mutualbackup/guild-invite/v1` |
| `GuildGenesis` | `format_version`, `guild_id`, `coordinator`, `members` | `mutualbackup/guild-genesis/v1`; hash derive-key context `mutualbackup guild genesis v1` |
| `QuorumGuildGenesis` | `genesis`, `signatures` | certificate of genesis signatures |
| `UserRevision` | `format_version`, `guild_id`, `protected_root_id`, `cipher_profile`, `revision_id`, `owner`, `writer_epoch`, `writer_public_key`, `writer_signature`, `sequence`, `parent`, `metadata_sectors`, `data_sectors` | stable signature `mutualbackup/user-revision/v3`; writer signature `mutualbackup/writer-revision/v1`; hash derive-key context `mutualbackup user revision body v3` |
| `WriterFence` | `owner`, `epoch`, `public_key` | embedded value; epochs for each owner are contiguous and permanently certified by checkpoints |
| `RevisionTombstone` | `owner`, `protected_root_id`, `through_sequence`, `last_revision_id`, `last_revision_hash`, `retired_at_generation` | embedded retained-prefix high-water mark for one protected-root chain; checkpoint signatures authorize retirement |
| `SectorRef` | `id`, `root`, `logical_len` | embedded value; sector root is BLAKE3 of exact RS-level bytes |
| `CodingGroup` | `id`, `format_version`, `guild_id`, `data_shards`, `parity_shards`, `shard_size`, five ordered `roles` | ID is BLAKE3 of the same fields except `id` |
| `InformationRole` | `owner`, `sector` | embedded value |
| `ParityRole` | `holder`, `row`, `root` | embedded value |
| `CodingAttemptPlan` | version 1: `format_version`, `attempt_id`, `checkpoint_hash`, `membership_epoch`, `geometry`, `delegator`, `coding_coordinator`, `verification_coordinator`, `expires_at_unix_seconds`; version 2 appends `information_roots` | `mutualbackup/coding-attempt-plan/v1`; version 2 binds every real Merkle input to the flat root in its signed user revision, while virtual-zero inputs use the zero sentinel; version 1 retains its byte-exact legacy layout |
| `CheckpointAuthority` | `format_version`, `membership_epoch`, `quorum` | embedded version-5 checkpoint authority; the epoch changes with roster, failure-domain, or quorum-policy authorization |
| `GuildCheckpoint` | versions 3–4: `format_version`, `guild_id`, `genesis_hash`, `generation`, `parent`, `members`, `writer_fences`, `revision_tombstones`, `revisions`, `coding_groups`; versions 5–6 append `authority` | `mutualbackup/guild-checkpoint/v1`; hash is BLAKE3 of canonical bytes; version 6 carries root-scoped revision/tombstone records |
| `QuorumCheckpoint` | `checkpoint`, `signatures` | certificate of checkpoint signatures; versions 3–4 require every listed member, while versions 5–6 require their epoch-bound guild quorum |
| `MemberSignature` | `signer`, `signature` | signature domain belongs to containing certificate |
| `StorageAcknowledgement` | `format_version`, `operation_id`, `guild_id`, `group_id`, `shard_index`, `row`, `root`, `holder` | `mutualbackup/storage-acknowledgement/v1` |
| `EndpointRecord` | `format_version`, `publisher`, `sequence`, `expires_at_unix_seconds`, `endpoints` | `mutualbackup/endpoint-record/v1` |
| `RecoveryLocator` | `format_version`, `subject`, `publisher`, `guild_id`, `checkpoint_hash`, `checkpoint_generation`, `subject_endpoint_sequence_floor`, `endpoints`, `expires_at_unix_seconds` | `mutualbackup/recovery-locator/v1`, then encrypted inside a recovery bundle; the floor is the publisher's greatest durable observation of the subject's endpoint sequence and lets a seed-recovered subject advance beyond expired DHT records |
| `SealedRecoveryRecord` | `format_version`, `ephemeral_public_key`, `nonce`, `ciphertext` | XChaCha20-Poly1305 with `mutualbackup/recovery-record/v1` associated context |
| `RecoveryBundle` | `format_version`, `subject`, `publisher`, `sequence`, `expires_at_unix_seconds`, `key_envelope`, `sealed` | `mutualbackup/recovery-bundle/v1`; format 1 has no envelope and uses the seed-derived recovery key, while format 2 carries the current quorum-authenticated recovery-key envelope and seals the locator to that epoch |
| peer request envelope | `format_version`, `request_id`, `caller`, `recipient`, `guild_scope`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `request` | `mutualbackup/direct-request/v2` |
| peer response envelope | `format_version`, `request_id`, `recipient`, `request_hash`, `result` | `mutualbackup/direct-response/v2` |

The recovery-string vector records whitespace normalization, Argon2id v1.3
parameters and derived identities. Other vector files are hexadecimal raw
Postcard or CBOR unless their extension says JSON.
