//! Read-only reconstruction from preserved, certified checkpoint data.

use crate::PreservedParityVolume;
use anyhow::{Context, Result, bail, ensure};
use mb_core::{
    CodingProfile, PackedSlot, QuorumCheckpoint, SectorRef, ShardRole, SignedRecord, UserRevision,
    V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes_bounded, canonical_size_bounded,
    decode_canonical, merkle_commit, packing_protected_root, reconstruct_3_2, sector_root,
    verify_codeword,
};
use mb_store::ControlStore;

// Each lookup finishes its SQLite statement before recovery can contact peers.
// Export's input-version guard rejects concurrent changes before publication.
fn for_each_recovery_record(
    control: &ControlStore,
    kind: &str,
    guard: &mb_store::PreservedReadGuard,
    mut visit: impl FnMut(&[u8], &[u8]) -> Result<bool>,
) -> Result<()> {
    let mut after = None;
    loop {
        guard.verify_unchanged()?;
        let Some((key, bytes)) =
            control.next_record_bounded(kind, after.as_deref(), 32, V1_MAX_CATALOG_BYTES)?
        else {
            break;
        };
        let more = visit(&key, &bytes)?;
        guard.verify_unchanged()?;
        if !more {
            break;
        }
        after = Some(key);
    }
    Ok(())
}

pub(super) struct RecoveryInputs<'a> {
    pub(super) control_guard: &'a mb_store::PreservedReadGuard,
    pub(super) volumes: &'a [PreservedParityVolume],
    pub(super) remote: Option<&'a super::remote::PeerRecovery>,
}

#[derive(Default)]
pub(super) struct CheckpointRecovery {
    checkpoint: Option<([u8; 32], QuorumCheckpoint)>,
    codeword: Option<DecodedCodeword>,
}

struct DecodedCodeword {
    checkpoint: [u8; 32],
    group: [u8; 32],
    shards: Vec<Vec<u8>>,
}

impl CheckpointRecovery {
    pub(super) fn with_checkpoint(checkpoint: Option<QuorumCheckpoint>) -> Result<Self> {
        Ok(Self {
            checkpoint: checkpoint
                .map(|checkpoint| -> Result<_> { Ok((checkpoint.hash()?, checkpoint)) })
                .transpose()?,
            codeword: None,
        })
    }

    pub(super) fn load(
        &mut self,
        control: &ControlStore,
        revision: &SignedRecord<UserRevision>,
        reference: &SectorRef,
        inputs: &RecoveryInputs<'_>,
    ) -> Result<Option<Vec<u8>>> {
        let mut last_error = None;
        if let Some((hash, checkpoint)) = &self.checkpoint {
            match recover(
                control,
                *hash,
                checkpoint,
                revision,
                reference,
                &mut self.codeword,
                inputs,
            ) {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(error) => last_error = Some(error),
            }
        }
        let previous = self.checkpoint.as_ref().map(|(hash, _)| *hash);
        let mut found = None;
        for_each_recovery_record(
            control,
            "guild-checkpoint",
            inputs.control_guard,
            |key, bytes| {
                if previous.is_some_and(|hash| key == hash) {
                    return Ok(true);
                }
                let checkpoint: QuorumCheckpoint = decode_canonical(bytes)?;
                if !checkpoint
                    .checkpoint
                    .revisions
                    .iter()
                    .any(|candidate| candidate == revision)
                {
                    return Ok(true);
                }
                ensure!(
                    canonical_bytes_bounded(&checkpoint, V1_MAX_CATALOG_BYTES)? == bytes,
                    "preserved checkpoint is not canonical"
                );
                checkpoint.verify()?;
                let hash = checkpoint.hash()?;
                ensure!(
                    key == hash,
                    "preserved checkpoint has a conflicting record hash"
                );
                match recover(
                    control,
                    hash,
                    &checkpoint,
                    revision,
                    reference,
                    &mut self.codeword,
                    inputs,
                ) {
                    Ok(bytes) => {
                        found = Some(bytes);
                        self.checkpoint = Some((hash, checkpoint));
                        Ok(false)
                    }
                    Err(error) => {
                        last_error = Some(error);
                        Ok(true)
                    }
                }
            },
        )?;
        if found.is_none()
            && let Some(remote) = inputs.remote
        {
            let origin = crate::node::preserved_guild_certificate(control)?
                .map(|certificate| -> Result<_> {
                    ensure!(
                        certificate.genesis.guild_id == revision.value.guild_id,
                        "preserved guild certificate conflicts with the requested revision"
                    );
                    Ok(certificate.hash()?)
                })
                .transpose()?;
            remote.checkpoints(revision.value.guild_id, origin, |checkpoint| {
                let hash = checkpoint.hash()?;
                if previous == Some(hash)
                    || !checkpoint
                        .checkpoint
                        .revisions
                        .iter()
                        .any(|candidate| candidate == revision)
                {
                    return Ok(true);
                }
                match recover(
                    control,
                    hash,
                    &checkpoint,
                    revision,
                    reference,
                    &mut self.codeword,
                    inputs,
                ) {
                    Ok(bytes) => {
                        found = Some(bytes);
                        self.checkpoint = Some((hash, checkpoint));
                        Ok(false)
                    }
                    Err(error) => {
                        last_error = Some(error);
                        Ok(true)
                    }
                }
            })?;
        }
        if found.is_some() {
            return Ok(found);
        }
        if let Some(error) = last_error {
            return Err(error).context("preserved checkpoint cannot reconstruct the requested sector; original records remain intact");
        }
        Ok(None)
    }
}

fn recover(
    control: &ControlStore,
    hash: [u8; 32],
    checkpoint: &QuorumCheckpoint,
    revision: &SignedRecord<UserRevision>,
    reference: &SectorRef,
    decoded: &mut Option<DecodedCodeword>,
    inputs: &RecoveryInputs<'_>,
) -> Result<Vec<u8>> {
    if checkpoint.checkpoint.packing_catalog.is_some() {
        return recover_packed(
            control, checkpoint, revision, reference, hash, decoded, inputs,
        );
    }
    for group in &checkpoint.checkpoint.coding_groups {
        let Some(index) = group.roles.iter().position(|role| matches!(role,
            ShardRole::Information(info) if info.owner == revision.value.owner && info.sector == *reference
        )) else { continue; };
        if let Some(cached) = decoded
            .as_ref()
            .filter(|cached| cached.checkpoint == hash && cached.group == group.id)
        {
            return Ok(cached.shards[index].clone());
        }
        let roots: Vec<_> = group
            .roles
            .iter()
            .map(|role| match role {
                ShardRole::Information(info) => info.sector.root,
                ShardRole::Parity(parity) => parity.root,
            })
            .collect();
        *decoded = None;
        let mut shards: Vec<_> = roots
            .iter()
            .enumerate()
            .map(|(index, root)| {
                control
                    .recovery_shard(&hash, &group.guild_id, &group.id, index as u8, root)
                    .ok()
                    .or_else(|| {
                        inputs.volumes.iter().find_map(|volume| {
                            volume
                                .load_fixed(&group.guild_id, &group.id, index as u8, root)
                                .ok()
                        })
                    })
            })
            .collect();
        // Historical filler positions may be zero-length. Infer their bytes
        // only when the certified full-sector root authenticates all zeros.
        let zero = vec![0; V1_SECTOR_SIZE];
        let zero_root = sector_root(&zero);
        for (index, role) in group.roles.iter().enumerate() {
            if shards[index].is_none()
                && matches!(role, ShardRole::Information(info)
                if info.sector.logical_len == 0 && info.sector.root == zero_root)
            {
                shards[index] = Some(zero.clone());
            }
        }
        if let Some(remote) = inputs.remote {
            for assigned_only in [true, false] {
                for position in (0..shards.len()).rev() {
                    if shards.iter().flatten().count() >= usize::from(group.data_shards) {
                        break;
                    }
                    if shards[position].is_none() {
                        shards[position] = remote.fixed(group, position, assigned_only);
                    }
                }
            }
        }
        reconstruct_3_2(&mut shards)
            .context("not enough authenticated cached shards for the certified 3+2 codeword")?;
        let shards: Vec<Vec<u8>> = shards
            .into_iter()
            .map(|shard| shard.context("reconstruction left a missing shard"))
            .collect::<Result<_>>()?;
        for (bytes, root) in shards.iter().zip(roots) {
            ensure!(
                sector_root(bytes) == root,
                "reconstructed codeword conflicts with a certified shard root"
            );
        }
        verify_codeword(CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32), &shards)?;
        let bytes = shards[index].clone();
        *decoded = Some(DecodedCodeword {
            checkpoint: hash,
            group: group.id,
            shards,
        });
        return Ok(bytes);
    }
    bail!("requested signed sector has no certified fixed-profile placement");
}

fn recover_packed(
    control: &ControlStore,
    checkpoint: &QuorumCheckpoint,
    revision: &SignedRecord<UserRevision>,
    reference: &SectorRef,
    checkpoint_hash: [u8; 32],
    decoded: &mut Option<DecodedCodeword>,
    inputs: &RecoveryInputs<'_>,
) -> Result<Vec<u8>> {
    let guild = checkpoint.checkpoint.guild_id;
    let catalog = checkpoint
        .checkpoint
        .packing_catalog
        .as_ref()
        .context("checkpoint has no packing catalog")?;
    let owner = revision.value.owner;
    let root = packing_protected_root(revision.value.protected_root_id);
    let matches = |source: &mb_core::PackedSourceChunk| {
        (
            source.id.owner,
            source.id.protected_root,
            source.id.object_id,
        ) == (owner, root, reference.id)
    };
    let mut output = vec![0; V1_SECTOR_SIZE];
    let mut present = vec![false; V1_SECTOR_SIZE];
    for descriptor in &catalog.sectors {
        if !descriptor
            .slots
            .iter()
            .any(|slot| slot.source().is_some_and(matches))
        {
            continue;
        }
        // Retain one packed payload, irrespective of how many descriptors
        // contain this object. The fixed-size output is never a shard catalog.
        let bytes = if descriptor
            .slots
            .iter()
            .all(|slot| matches!(slot, PackedSlot::VirtualZero { .. }))
        {
            vec![0; catalog.profile.sector_size as usize]
        } else {
            let limit = canonical_size_bounded(descriptor, V1_MAX_CATALOG_BYTES)?
                .checked_add(catalog.profile.sector_size as usize + 64)
                .context("packed record size overflow")?;
            let key: Vec<_> = guild.iter().chain(&descriptor.id).copied().collect();
            let cached = (|| -> Result<Vec<u8>> {
                let encoded = control
                    .get_record_bounded("packed-sector", &key, limit)?
                    .context("certified packed sector is unavailable")?;
                let record: crate::node::PackedSectorRecord = decode_canonical(&encoded)?;
                ensure!(
                    record.format_version == 1
                        && record.guild_id == guild
                        && record.sector.descriptor == *descriptor,
                    "preserved packed record differs from its certified descriptor"
                );
                ensure!(
                    merkle_commit(&record.sector.bytes)? == descriptor.commitment,
                    "preserved packed payload failed its certified commitment"
                );
                Ok(record.sector.bytes)
            })();
            match cached {
                Ok(bytes) => bytes,
                Err(error) if inputs.volumes.is_empty() && inputs.remote.is_none() => {
                    return Err(error);
                }
                Err(_) => recover_variable(
                    control,
                    checkpoint,
                    checkpoint_hash,
                    descriptor,
                    decoded,
                    inputs,
                )?,
            }
        };
        ensure!(
            bytes.len() == catalog.profile.sector_size as usize
                && (catalog.format_version >= 3 || sector_root(&bytes) == descriptor.flat_root)
                && merkle_commit(&bytes)? == descriptor.commitment,
            "preserved packed payload failed its certified root or commitment"
        );
        for (index, slot) in descriptor.slots.iter().enumerate() {
            let Some(source) = slot.source().filter(|source| matches(source)) else {
                continue;
            };
            let start = usize::try_from(source.source_offset)?;
            let end = start
                .checked_add(source.logical_len as usize)
                .context("packed source range overflow")?;
            ensure!(
                end <= output.len() && !present[start..end].iter().any(|present| *present),
                "packed source has overlapping or oversized ranges"
            );
            let source_bytes = match slot {
                PackedSlot::Data(_) => {
                    let offset = index
                        .checked_mul(catalog.profile.slot_size as usize)
                        .context("packed slot offset overflow")?;
                    bytes
                        .get(offset..offset + source.logical_len as usize)
                        .context("packed slot range is unavailable")?
                }
                PackedSlot::VirtualZero { .. } => &output[start..end],
            };
            ensure!(
                sector_root(source_bytes) == source.content_hash,
                "packed chunk differs from its certified content hash"
            );
            if matches!(slot, PackedSlot::Data(_)) {
                let offset = index * catalog.profile.slot_size as usize;
                output[start..end]
                    .copy_from_slice(&bytes[offset..offset + source.logical_len as usize]);
            }
            present[start..end].fill(true);
        }
    }
    ensure!(
        present.iter().all(|present| *present) && sector_root(&output) == reference.root,
        "unpacked ciphertext conflicts with its owner-signed sector"
    );
    Ok(output)
}

fn recover_variable(
    control: &ControlStore,
    checkpoint: &QuorumCheckpoint,
    checkpoint_hash: [u8; 32],
    descriptor: &mb_core::PackedSectorDescriptor,
    decoded: &mut Option<DecodedCodeword>,
    inputs: &RecoveryInputs<'_>,
) -> Result<Vec<u8>> {
    let guild = checkpoint.checkpoint.guild_id;
    // An intact information copy needs only the certified descriptor. Its
    // position can change between retained groups, but its storage key cannot.
    for index in 0..mb_core::MAX_CODING_SHARDS {
        for volume in inputs.volumes {
            if let Ok(bytes) =
                volume.load_variable(&guild, &descriptor.id, index, &descriptor.commitment)
            {
                return Ok(bytes);
            }
        }
    }
    let mut found = None;
    let mut last_error = None;
    for_each_recovery_record(
        control,
        "coding-group-transcript",
        inputs.control_guard,
        |key, encoded| {
            let transcript: SignedRecord<mb_core::CodingVerificationTranscript> =
                decode_canonical(encoded)?;
            let group = &transcript.value.manifest.value.group;
            if group.guild_id != guild {
                return Ok(true);
            }
            let Some(wanted) = group.roles.iter().position(|role| {
            matches!(role,
                mb_core::ShardRoleV2::Information(info) if info.sector.id == descriptor.id
                    && info.sector.commitment == descriptor.commitment && !info.sector.virtual_zero
            )
        }) else {
            return Ok(true);
        };
            let attempt = (|| -> Result<_> {
                ensure!(
                    key == group.id
                        && canonical_bytes_bounded(&transcript, V1_MAX_CATALOG_BYTES)? == encoded,
                    "preserved coding transcript has a conflicting identity or encoding"
                );
                recover_variable_transcript(&transcript, checkpoint_hash, wanted, decoded, inputs)
            })();
            match attempt {
                Ok(bytes) => {
                    found = Some(bytes);
                    Ok(false)
                }
                Err(error) => {
                    last_error = Some(error);
                    Ok(true)
                }
            }
        },
    )?;
    if found.is_none()
        && let Some(remote) = inputs.remote
    {
        remote.transcripts(control, checkpoint, descriptor, |transcript| {
            let group = &transcript.value.manifest.value.group;
            let Some(wanted) = group.roles.iter().position(|role| matches!(role,
                mb_core::ShardRoleV2::Information(info) if info.sector.id == descriptor.id
                    && info.sector.commitment == descriptor.commitment && !info.sector.virtual_zero
            )) else { return Ok(true); };
            match recover_variable_transcript(&transcript, checkpoint_hash, wanted, decoded, inputs)
            {
                Ok(bytes) => {
                    found = Some(bytes);
                    Ok(false)
                }
                Err(error) => {
                    last_error = Some(error);
                    Ok(true)
                }
            }
        })?;
    }
    found.ok_or_else(|| {
        last_error.unwrap_or_else(|| {
            anyhow::anyhow!("certified packed sector has no available verified variable placement")
        })
    })
}

fn recover_variable_transcript(
    transcript: &SignedRecord<mb_core::CodingVerificationTranscript>,
    checkpoint_hash: [u8; 32],
    wanted: usize,
    decoded: &mut Option<DecodedCodeword>,
    inputs: &RecoveryInputs<'_>,
) -> Result<Vec<u8>> {
    let group = &transcript.value.manifest.value.group;
    let guild = group.guild_id;
    ensure!(
        mb_core::replay_coding_transcript(transcript)? == mb_core::CodingReplayFinding::Verified,
        "preserved coding transcript did not verify"
    );
    if let Some(cached) = decoded
        .as_ref()
        .filter(|cached| cached.checkpoint == checkpoint_hash && cached.group == group.id)
    {
        return Ok(cached.shards[wanted].clone());
    }
    // Drop the previous codeword before allocating the next one. All
    // geometry comes from the verified transcript, never local defaults.
    *decoded = None;
    let mut shards = Vec::with_capacity(group.profile.total_shards()?);
    let mut commitments = Vec::with_capacity(group.roles.len());
    for (index, role) in group.roles.iter().enumerate() {
        let (storage_key, commitment, zero) = match role {
            mb_core::ShardRoleV2::Information(info) => (
                info.sector.id,
                &info.sector.commitment,
                info.sector.virtual_zero,
            ),
            mb_core::ShardRoleV2::Parity(parity) => (group.id, &parity.commitment, false),
        };
        let bytes = if zero {
            Some(vec![0; group.profile.shard_size as usize])
        } else {
            inputs
                .volumes
                .iter()
                .find_map(|volume| {
                    volume
                        .load_variable(&guild, &storage_key, index as u16, commitment)
                        .ok()
                })
                .or_else(|| {
                    transcript
                        .value
                        .manifest
                        .value
                        .information_bytes
                        .as_ref()
                        .and_then(|bytes| bytes.get(index))
                        .cloned()
                        .flatten()
                })
        };
        shards.push(bytes);
        commitments.push(commitment);
    }
    if let Some(remote) = inputs.remote {
        for assigned_only in [true, false] {
            for position in (0..shards.len()).rev() {
                if shards.iter().flatten().count() >= usize::from(group.profile.data_shards) {
                    break;
                }
                if shards[position].is_none() {
                    shards[position] = remote.variable(group, position, assigned_only);
                }
            }
        }
    }
    mb_core::reconstruct(group.profile, &mut shards)
        .context("not enough authenticated preserved variable shards")?;
    let shards: Vec<Vec<u8>> = shards
        .into_iter()
        .map(|bytes| bytes.context("variable reconstruction left a missing position"))
        .collect::<Result<_>>()?;
    for (bytes, commitment) in shards.iter().zip(commitments) {
        ensure!(
            merkle_commit(bytes)? == *commitment,
            "reconstructed variable codeword conflicts with its signed commitment"
        );
    }
    verify_codeword(group.profile, &shards)?;
    let bytes = shards[wanted].clone();
    *decoded = Some(DecodedCodeword {
        checkpoint: checkpoint_hash,
        group: group.id,
        shards,
    });
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_record_callbacks_release_sqlite_snapshots_before_peer_work() {
        for kind in ["guild-checkpoint", "coding-group-transcript"] {
            let area = tempfile::tempdir().unwrap();
            let path = area.path().join("control.db");
            let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            writer
                .database_shell_statement("PRAGMA busy_timeout=0", false)
                .unwrap();
            for key in [b"a", b"b"] {
                writer.put_record(kind, key, b"preserved").unwrap();
            }
            let (reader, guard) =
                ControlStore::open_preserved_read_only_with_keys(&path, &[[7; 32]]).unwrap();
            let mut visited = Vec::new();
            let error = for_each_recovery_record(&reader, kind, &guard, |key, bytes| {
                assert_eq!(bytes, b"preserved");
                visited.push(key.to_vec());
                // This callback stands in for a slow peer request. A retained
                // SELECT cursor would leave checkpointing busy throughout it.
                writer.put_record("progress", b"id", key)?;
                let checkpoint =
                    writer.database_shell_statement("PRAGMA wal_checkpoint(TRUNCATE)", false)?;
                assert_eq!(
                    checkpoint.rows[0][0], "0",
                    "recovery retained a SQL read lock"
                );
                Ok(true)
            })
            .unwrap_err();
            assert!(error.to_string().contains("changed"), "{error:#}");
            assert_eq!(visited, [b"a".to_vec()]);
            assert!(
                guard.verify_unchanged().is_err(),
                "changed recovery inputs must not publish"
            );
        }
    }
}
