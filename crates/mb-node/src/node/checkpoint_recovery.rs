//! Recover one signed source from exact retained packing/coding evidence.
//! Chunk locators are hints. Original coding roots and complete source roots
//! authenticate every byte before the caller can decrypt or publish it.

use anyhow::{Context, Result, ensure};
use mb_core::{
    CatalogCodingEntry, CatalogCodingTraversalBudget as Work, CatalogScope, CatalogSectorRecord,
    MerkleCommitment, NodeId, PackingProfile, ShardRoleV2, SourceChunkId, canonical_bytes,
    merkle_commit, packing_protected_root, sector_root,
};
use mb_store::CatalogCheckpointChunkLocation;

type Location = (PackingProfile, CatalogCheckpointChunkLocation);

pub(super) fn recover_source(
    original: &CatalogSectorRecord,
    scope: CatalogScope,
    budget: Work,
    mut locate: impl FnMut(SourceChunkId) -> Result<Option<Location>>,
    mut group: impl FnMut([u8; 32], Work) -> Result<Option<CatalogCodingEntry>>,
    mut shard: impl FnMut([u8; 32], u16, NodeId, &MerkleCommitment, [u8; 32]) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let CatalogScope::Dataset {
        guild_id,
        owner,
        protected_root_id,
    } = scope
    else {
        anyhow::bail!("source recovery requires its original dataset scope")
    };
    original.commitment.validate()?;
    ensure!(
        original.commitment.byte_len <= mb_core::MAX_PROFILE_SHARD_SIZE,
        "recovery source exceeds the supported geometry"
    );
    let mut source = SourceChunkId {
        owner,
        protected_root: packing_protected_root(protected_root_id),
        object_id: original.sector.id,
        chunk_index: 0,
    };
    let (profile, first) = locate(source)?.context("retained source has no packing locator")?;
    profile.validate()?;
    ensure!(
        profile.sector_size == original.commitment.byte_len,
        "packing profile differs from the original source length"
    );
    let width = profile.slots_per_sector()?;
    let available = budget.remaining_after(Work {
        bytes: u64::from(original.commitment.byte_len),
        ..Work::default()
    })?;
    let mut output = vec![0; original.commitment.byte_len as usize];
    let mut cached: Option<([u8; 32], u16, Vec<u8>)> = None;
    // Divide the operation envelope once. No chunk resets the caller's budget.
    let piece = Work {
        bytes: available.bytes / u64::from(width),
        page_occurrences: available.page_occurrences / u64::from(width),
        records: available.records / u64::from(width),
    };
    for chunk in 0..width {
        source.chunk_index = chunk;
        let (actual_profile, location) = if chunk == 0 {
            (profile, first)
        } else {
            locate(source)?.context("retained source has an incomplete packing locator")?
        };
        ensure!(
            actual_profile == profile && location.slot_index < width,
            "retained source packing geometry changed"
        );
        if cached
            .as_ref()
            .is_none_or(|(id, index, _)| *id != location.group_id || *index != location.shard_index)
        {
            // The complete worst-case codeword fits a bounded allocation. Its
            // work is reserved before original witness replay and shard I/O.
            let witness = Work {
                bytes: piece.bytes / 2,
                records: piece.records / 2,
                page_occurrences: piece.page_occurrences,
            };
            let entry = group(location.group_id, witness)?
                .context("retained packing group is unavailable")?;
            let coding = &entry.retained.group;
            coding.validate()?;
            ensure!(
                coding.id == location.group_id
                    && coding.guild_id == guild_id
                    && coding.profile.shard_size == profile.sector_size
                    && location.shard_index < coding.profile.data_shards,
                "packing locator differs from its original coding group"
            );
            let ShardRoleV2::Information(target) = &coding.roles[usize::from(location.shard_index)]
            else {
                anyhow::bail!("packing locator selects a parity role")
            };
            ensure!(
                target.sector.id == location.sector_id,
                "packing locator selects another original sector"
            );
            piece.remaining_after(witness)?.remaining_after(Work {
                bytes: (coding.profile.total_shards()? as u64 + 2) * u64::from(profile.sector_size)
                    + u64::from(original.commitment.byte_len),
                records: coding.roles.len() as u64 + 1,
                page_occurrences: 0,
            })?;
            let transcript = *blake3::hash(&canonical_bytes(&entry.transcript)?).as_bytes();
            let mut shards = Vec::with_capacity(coding.roles.len());
            for (index, role) in coding.roles.iter().enumerate() {
                let (holder, commitment, zero) = match role {
                    ShardRoleV2::Information(role) => (
                        role.owner,
                        &role.sector.commitment,
                        role.sector.virtual_zero,
                    ),
                    ShardRoleV2::Parity(role) => (role.holder, &role.commitment, false),
                };
                let bytes = if zero {
                    Some(vec![0; coding.profile.shard_size as usize])
                } else {
                    shard(coding.id, index as u16, holder, commitment, transcript)?
                };
                if let Some(bytes) = &bytes {
                    ensure!(
                        merkle_commit(bytes)? == *commitment,
                        "retained shard fails its original full commitment"
                    );
                }
                shards.push(bytes);
            }
            if shards[usize::from(location.shard_index)].is_none() {
                mb_core::reconstruct(coding.profile, &mut shards)?;
            }
            let bytes = shards[usize::from(location.shard_index)]
                .take()
                .context("retained roles cannot recover the packed sector")?;
            ensure!(
                merkle_commit(&bytes)? == target.sector.commitment,
                "reconstructed packed sector fails its original commitment"
            );
            if let Some(roots) = &entry.transcript.value.plan.value.information_roots {
                ensure!(
                    sector_root(&bytes) == roots[usize::from(location.shard_index)],
                    "reconstructed packed sector fails its original byte root"
                );
            }
            cached = Some((location.group_id, location.shard_index, bytes));
        }
        let packed = &cached
            .as_ref()
            .context("missing recovered packed sector")?
            .2;
        let from = location.slot_index as usize * profile.slot_size as usize;
        let to = chunk as usize * profile.slot_size as usize;
        output[to..to + profile.slot_size as usize]
            .copy_from_slice(&packed[from..from + profile.slot_size as usize]);
    }
    ensure!(
        merkle_commit(&output)? == original.commitment
            && sector_root(&output) == original.sector.root,
        "recovered source fails its original complete commitment"
    );
    Ok(output)
}
