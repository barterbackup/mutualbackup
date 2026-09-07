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
| `UserRevision` | `format_version`, `guild_id`, `cipher_profile`, `revision_id`, `owner`, `sequence`, `parent`, `metadata_sectors`, `data_sectors` | `mutualbackup/user-revision/v1`; hash derive-key context `mutualbackup user revision body v1` |
| `SectorRef` | `id`, `root`, `logical_len` | embedded value; sector root is BLAKE3 of exact RS-level bytes |
| `CodingGroup` | `id`, `format_version`, `guild_id`, `data_shards`, `parity_shards`, `shard_size`, five ordered `roles` | ID is BLAKE3 of the same fields except `id` |
| `InformationRole` | `owner`, `sector` | embedded value |
| `ParityRole` | `holder`, `row`, `root` | embedded value |
| `GuildCheckpoint` | `format_version`, `guild_id`, `genesis_hash`, `generation`, `parent`, `members`, `revisions`, `coding_groups` | `mutualbackup/guild-checkpoint/v1`; hash is BLAKE3 of canonical bytes |
| `QuorumCheckpoint` | `checkpoint`, `signatures` | certificate of checkpoint signatures |
| `MemberSignature` | `signer`, `signature` | signature domain belongs to containing certificate |
| `StorageAcknowledgement` | `format_version`, `operation_id`, `guild_id`, `group_id`, `shard_index`, `row`, `root`, `holder` | `mutualbackup/storage-ack/v1` |
| `EndpointRecord` | `format_version`, `publisher`, `sequence`, `expires_at_unix_seconds`, `endpoints` | `mutualbackup/endpoint-record/v1` |
| `RecoveryLocator` | `format_version`, `subject`, `publisher`, `guild_id`, `checkpoint_hash`, `checkpoint_generation`, `endpoints`, `expires_at_unix_seconds` | encrypted inside a recovery bundle |
| `SealedRecoveryRecord` | `format_version`, `ephemeral_public_key`, `nonce`, `ciphertext` | XChaCha20-Poly1305 with `mutualbackup/recovery-record/v1` associated context |
| `RecoveryBundle` | `format_version`, `subject`, `publisher`, `sequence`, `expires_at_unix_seconds`, `sealed` | `mutualbackup/recovery-bundle/v1` |
| peer request envelope | `format_version`, `request_id`, `caller`, `recipient`, `guild_scope`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `request` | `mutualbackup/direct-request/v2` |
| peer response envelope | `format_version`, `request_id`, `recipient`, `request_hash`, `result` | `mutualbackup/direct-response/v2` |

The recovery-string vector records whitespace normalization, Argon2id v1.3
parameters and derived identities. Other vector files are hexadecimal raw
Postcard or CBOR unless their extension says JSON.
