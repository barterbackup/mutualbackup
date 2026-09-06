use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mb_core::{
    GuildCheckpoint, KeyMaterial, Member, MemberSignature, NodeId, QuorumCheckpoint,
    RecoveryLocator, SectorId, SectorRef, Seed, ShardRole, SignedRecord, UserRevision,
    canonical_bytes, decode_canonical, seal_recovery_record, sector_root, synthetic_filler_sector,
};
use mb_store::{ControlStore, ParityObject, ParityStore};
use uuid::Uuid;

use crate::snapshot::{
    install_inline_recipe, install_recovered_sector_recipe, prepare_revision, render_sector,
};

pub struct Node {
    data_dir: PathBuf,
    keys: KeyMaterial,
    control: ControlStore,
    parity: ParityStore,
}

impl Node {
    pub fn open(data_dir: impl AsRef<Path>, seed: Seed) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        set_private_directory(&data_dir)?;
        let keys = KeyMaterial::from_seed(&seed);
        let mut volume_id = [0_u8; 16];
        volume_id.copy_from_slice(&blake3::hash(&keys.node_id().0).as_bytes()[..16]);
        let control = ControlStore::open(data_dir.join("control.db"), &keys)?;
        let parity = ParityStore::open(data_dir.join("parity.db"), &volume_id, &keys)?;
        Ok(Self {
            data_dir,
            keys,
            control,
            parity,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn keys(&self) -> &KeyMaterial {
        &self.keys
    }

    pub fn member(&self, failure_domain: impl Into<String>) -> Member {
        Member {
            node_id: self.keys.node_id(),
            recovery_public_key: self.keys.recovery_public_key(),
            failure_domain: failure_domain.into(),
        }
    }

    pub fn prepare_revision(
        &mut self,
        guild_id: [u8; 32],
        source_root: &Path,
        sequence: u64,
    ) -> Result<SignedRecord<UserRevision>> {
        prepare_revision(
            &mut self.control,
            &self.keys,
            guild_id,
            source_root,
            sequence,
        )
    }

    pub fn ensure_filler(
        &mut self,
        guild_id: [u8; 32],
        revision_id: Uuid,
        ordinal: u64,
    ) -> Result<(SectorRef, Vec<u8>)> {
        let (reference, bytes) = synthetic_filler_sector(
            &self.keys.guild_data_key(&guild_id),
            self.keys.node_id(),
            revision_id,
            ordinal,
        )?;
        install_inline_recipe(&mut self.control, guild_id, reference.clone(), Vec::new())?;
        Ok((reference, bytes))
    }

    pub fn sector(&self, sector_id: &SectorId) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id)
    }

    pub fn publish_parity(&mut self, object: &ParityObject) -> Result<()> {
        self.parity.stage_and_publish(object)?;
        Ok(())
    }

    pub fn parity(&self, group_id: &[u8; 32], shard_index: u8) -> Result<Vec<u8>> {
        Ok(self.parity.load_ready(group_id, shard_index)?.bytes)
    }

    pub fn store_checkpoint(&mut self, checkpoint: &QuorumCheckpoint) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint)?;
        if !checkpoint.has_signature(self.keys.node_id()) {
            anyhow::bail!("local node did not authorize this checkpoint");
        }
        let hash = checkpoint.hash()?;
        let body = canonical_bytes(&checkpoint.checkpoint)?;
        let certificate = canonical_bytes(checkpoint)?;
        self.control.commit_checkpoint(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &hash,
            &body,
            &certificate,
            true,
        )?;
        Ok(hash)
    }

    pub fn sign_checkpoint(&mut self, checkpoint: &GuildCheckpoint) -> Result<MemberSignature> {
        checkpoint.validate()?;
        self.validate_local_member(checkpoint)?;
        self.validate_checkpoint_transition(checkpoint)?;
        self.validate_local_roles(checkpoint)?;
        let hash = checkpoint.hash()?;
        let body = canonical_bytes(checkpoint)?;
        self.control.lock_checkpoint_signature(
            &checkpoint.guild_id,
            checkpoint.generation,
            checkpoint.parent.as_ref(),
            &hash,
            &body,
        )?;
        Ok(checkpoint.member_signature(&self.keys)?)
    }

    fn validate_local_member(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        let member = checkpoint
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("checkpoint does not contain the local node")?;
        if member.recovery_public_key != self.keys.recovery_public_key() {
            anyhow::bail!("checkpoint recovery key does not match the local seed");
        }
        Ok(())
    }

    fn validate_checkpoint_transition(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        let locked = self.control.locked_checkpoint(&checkpoint.guild_id)?;
        let head = self.control.checkpoint_head(&checkpoint.guild_id)?;
        let previous = match (locked, head) {
            (Some(locked), Some(head)) if locked.0 >= head.0 => {
                Some((locked.0, locked.1, locked.2, true))
            }
            (Some(_), Some(head)) => Some((head.0, head.1, head.2, false)),
            (Some(locked), None) => Some((locked.0, locked.1, locked.2, true)),
            (None, Some(head)) => Some((head.0, head.1, head.2, false)),
            (None, None) => None,
        };
        let Some((generation, hash, bytes, is_body)) = previous else {
            if checkpoint.generation != 1 || checkpoint.parent.is_some() {
                anyhow::bail!("first checkpoint must be generation one");
            }
            return Ok(());
        };
        if generation == checkpoint.generation && hash == checkpoint.hash()? {
            return Ok(());
        }
        if generation.checked_add(1) != Some(checkpoint.generation)
            || checkpoint.parent != Some(hash)
        {
            anyhow::bail!("checkpoint does not extend the locally accepted head");
        }
        let previous = if is_body {
            decode_canonical::<GuildCheckpoint>(&bytes)?
        } else {
            decode_canonical::<QuorumCheckpoint>(&bytes)?.checkpoint
        };
        if !previous.members.iter().all(|item| {
            checkpoint
                .members
                .binary_search_by_key(&item.node_id, |entry| entry.node_id)
                .is_ok_and(|index| checkpoint.members[index] == *item)
        }) || !previous
            .revisions
            .iter()
            .all(|item| checkpoint.revisions.contains(item))
            || !previous.coding_groups.iter().all(|item| {
                checkpoint
                    .coding_groups
                    .binary_search_by_key(&item.id, |entry| entry.id)
                    .is_ok_and(|index| checkpoint.coding_groups[index] == *item)
            })
        {
            anyhow::bail!("checkpoint transition drops or changes active state");
        }
        Ok(())
    }

    fn validate_local_roles(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        for group in &checkpoint.coding_groups {
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRole::Information(information)
                        if information.owner == self.keys.node_id() =>
                    {
                        let bytes = self.sector(&information.sector.id)?;
                        if bytes.len() != group.shard_size as usize
                            || sector_root(&bytes) != information.sector.root
                        {
                            anyhow::bail!("local information shard is not durable");
                        }
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let object = self.parity.load_ready(&group.id, index as u8)?;
                        if object.format_version != group.format_version
                            || object.guild_id != checkpoint.guild_id
                            || object.root != parity.root
                        {
                            anyhow::bail!("local parity shard is not durable");
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn recovery_record(
        &self,
        subject: &Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        endpoint: String,
        expires_at_unix_seconds: u64,
    ) -> Result<mb_core::SealedRecoveryRecord> {
        let locator = RecoveryLocator {
            format_version: 1,
            subject: subject.node_id,
            publisher: self.keys.node_id(),
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            endpoints: vec![endpoint],
            expires_at_unix_seconds,
        };
        let signed = SignedRecord::sign(b"mutualbackup/recovery-locator/v1", locator, &self.keys)?;
        Ok(seal_recovery_record(
            subject.recovery_public_key,
            &canonical_bytes(&signed)?,
        )?)
    }

    pub fn checkpoint(&self, hash: &[u8; 32]) -> Result<QuorumCheckpoint> {
        let bytes = self
            .control
            .get_record("guild-checkpoint", hash)?
            .context("checkpoint is unavailable")?;
        let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
        checkpoint.verify()?;
        if checkpoint.hash()? != *hash {
            anyhow::bail!("checkpoint hash mismatch");
        }
        Ok(checkpoint)
    }

    pub fn install_recovered_checkpoint(
        &mut self,
        checkpoint: &QuorumCheckpoint,
        recovered_shards: &BTreeMap<([u8; 32], u8), Vec<u8>>,
    ) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint)?;
        if !checkpoint.has_signature(self.keys.node_id()) {
            anyhow::bail!("checkpoint is not authorized by the recovering seed");
        }
        let mut expected = 0_usize;
        for group in &checkpoint.checkpoint.coding_groups {
            for (index, role) in group.roles.iter().enumerate() {
                let local = match role {
                    ShardRole::Information(information)
                        if information.owner == self.keys.node_id() =>
                    {
                        let bytes = recovered_shards
                            .get(&(group.id, index as u8))
                            .context("recovery omitted a local information shard")?;
                        install_recovered_sector_recipe(
                            &mut self.control,
                            &self.keys,
                            checkpoint.checkpoint.guild_id,
                            information.sector.clone(),
                            bytes,
                        )?;
                        true
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let bytes = recovered_shards
                            .get(&(group.id, index as u8))
                            .context("recovery omitted a local parity shard")?;
                        self.publish_parity(&ParityObject {
                            format_version: group.format_version,
                            guild_id: checkpoint.checkpoint.guild_id,
                            group_id: group.id,
                            shard_index: index as u8,
                            root: parity.root,
                            bytes: bytes.clone(),
                        })?;
                        true
                    }
                    _ => false,
                };
                expected += usize::from(local);
            }
        }
        if recovered_shards.len() != expected {
            anyhow::bail!("recovery supplied unexpected local shards");
        }
        self.validate_local_roles(&checkpoint.checkpoint)?;
        let hash = checkpoint.hash()?;
        self.control.commit_checkpoint(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &hash,
            &canonical_bytes(&checkpoint.checkpoint)?,
            &canonical_bytes(checkpoint)?,
            false,
        )?;
        Ok(hash)
    }

    pub fn cached_operation(
        &self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: NodeId,
        request_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .control
            .operation_result(operation_id, kind, &caller.0, request_hash)?)
    }

    pub fn commit_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: NodeId,
        request_hash: &[u8; 32],
        result: &[u8],
    ) -> Result<()> {
        self.control
            .put_operation_result(operation_id, kind, &caller.0, request_hash, result)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}
