//! Read-only reconstruction from preserved, certified checkpoint data.

use anyhow::{Context, Result, bail, ensure};
use mb_core::{
    CodingProfile, PackedSlot, QuorumCheckpoint, SectorRef, ShardRole, SignedRecord, UserRevision,
    V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes_bounded, canonical_size_bounded,
    decode_canonical, merkle_commit, packing_protected_root, reconstruct_3_2, sector_root,
    verify_codeword,
};
use mb_store::ControlStore;

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
    pub(super) fn load(
        &mut self,
        control: &ControlStore,
        revision: &SignedRecord<UserRevision>,
        reference: &SectorRef,
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
            ) {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(error) => last_error = Some(error),
            }
        }
        let previous = self.checkpoint.as_ref().map(|(hash, _)| *hash);
        let mut found = None;
        control.for_each_record_bounded(
            "guild-checkpoint",
            32,
            V1_MAX_CATALOG_BYTES,
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
) -> Result<Vec<u8>> {
    if let Some(catalog) = &checkpoint.checkpoint.packing_catalog {
        return recover_packed(
            control,
            checkpoint.checkpoint.guild_id,
            catalog,
            revision,
            reference,
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
        let mut shards: Vec<_> = roots
            .iter()
            .enumerate()
            .map(|(index, root)| {
                control
                    .recovery_shard(&hash, &group.guild_id, &group.id, index as u8, root)
                    .ok()
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
    guild: [u8; 32],
    catalog: &mb_core::PackedCatalog,
    revision: &SignedRecord<UserRevision>,
    reference: &SectorRef,
) -> Result<Vec<u8>> {
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
            .any(|slot| slot.source().is_some_and(&matches))
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
            record.sector.bytes
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
