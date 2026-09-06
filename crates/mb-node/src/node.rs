use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mb_core::{
    GuildCheckpoint, KeyMaterial, Member, MemberSignature, QuorumCheckpoint, RecoveryLocator,
    SectorId, SectorRef, Seed, SignedRecord, UserRevision, canonical_bytes, decode_canonical,
    seal_recovery_record, synthetic_filler_sector,
};
use mb_store::{ControlStore, ParityObject, ParityStore};
use uuid::Uuid;

use crate::snapshot::{install_inline_recipe, prepare_revision, render_sector};

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
        let hash = checkpoint.hash()?;
        self.control
            .put_record("guild-checkpoint", &hash, &canonical_bytes(checkpoint)?)?;
        Ok(hash)
    }

    pub fn sign_checkpoint(&self, checkpoint: &GuildCheckpoint) -> Result<MemberSignature> {
        Ok(checkpoint.member_signature(&self.keys)?)
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

    pub fn rebuild_from_checkpoint(&mut self, checkpoint: &QuorumCheckpoint) -> Result<()> {
        self.store_checkpoint(checkpoint)?;
        Ok(())
    }

    pub fn cached_operation(&self, operation_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        Ok(self.control.operation_result(operation_id)?)
    }

    pub fn commit_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        result: &[u8],
    ) -> Result<()> {
        self.control
            .put_operation_result(operation_id, kind, result)?;
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
