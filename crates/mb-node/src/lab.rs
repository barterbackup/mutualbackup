use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use mb_core::{
    CodingGroup, GuildCheckpoint, InformationRole, KeyMaterial, Member, NodeId, ParityRole,
    QuorumCheckpoint, RecoveryLocator, SectorId, SectorRef, Seed, ShardRole, SignedRecord,
    UserRevision, V1_SECTOR_SIZE, canonical_bytes, decode_canonical, encode_3_2,
    open_recovery_record, reconstruct_3_2, seal_recovery_record, sector_root,
};
use mb_store::ParityObject;

use crate::{Node, restore_revision};

type SharedNode = Arc<Mutex<Node>>;

#[derive(Clone, Default)]
pub struct MemoryNetwork {
    nodes: Arc<Mutex<BTreeMap<NodeId, SharedNode>>>,
}

impl MemoryNetwork {
    pub fn register(&self, node: SharedNode) -> Result<()> {
        let node_id = node.lock().map_err(lock_error)?.keys().node_id();
        self.nodes.lock().map_err(lock_error)?.insert(node_id, node);
        Ok(())
    }

    pub fn remove(&self, node_id: NodeId) -> Result<()> {
        self.nodes.lock().map_err(lock_error)?.remove(&node_id);
        Ok(())
    }

    fn node(&self, node_id: NodeId) -> Result<SharedNode> {
        self.nodes
            .lock()
            .map_err(lock_error)?
            .get(&node_id)
            .cloned()
            .with_context(|| format!("peer {node_id} is unreachable"))
    }

    fn sector(&self, node_id: NodeId, sector_id: &SectorId) -> Result<Vec<u8>> {
        self.node(node_id)?
            .lock()
            .map_err(lock_error)?
            .sector(sector_id)
    }

    fn parity(&self, node_id: NodeId, group_id: &[u8; 32], index: u8) -> Result<Vec<u8>> {
        self.node(node_id)?
            .lock()
            .map_err(lock_error)?
            .parity(group_id, index)
    }

    fn checkpoint(&self, node_id: NodeId, hash: &[u8; 32]) -> Result<QuorumCheckpoint> {
        self.node(node_id)?
            .lock()
            .map_err(lock_error)?
            .checkpoint(hash)
    }
}

#[derive(Clone, Default)]
pub struct MemoryDirectory {
    records: Arc<Mutex<BTreeMap<NodeId, BTreeMap<NodeId, mb_core::SealedRecoveryRecord>>>>,
}

impl MemoryDirectory {
    pub fn publish(
        &self,
        subject: NodeId,
        publisher: NodeId,
        record: mb_core::SealedRecoveryRecord,
    ) -> Result<()> {
        self.records
            .lock()
            .map_err(lock_error)?
            .entry(subject)
            .or_default()
            .insert(publisher, record);
        Ok(())
    }

    pub fn lookup(&self, subject: NodeId) -> Result<Vec<mb_core::SealedRecoveryRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(lock_error)?
            .get(&subject)
            .map(|publishers| publishers.values().cloned().collect())
            .unwrap_or_default())
    }
}

pub struct PrototypeGuild {
    guild_id: [u8; 32],
    members: Vec<Member>,
    nodes: Vec<Option<SharedNode>>,
    network: MemoryNetwork,
    directory: MemoryDirectory,
}

impl PrototypeGuild {
    pub fn create(root: &Path, seeds: Vec<Seed>) -> Result<Self> {
        if seeds.len() != 5 {
            bail!("the first prototype profile requires exactly five nodes");
        }
        fs::create_dir_all(root)?;
        let network = MemoryNetwork::default();
        let directory = MemoryDirectory::default();
        let mut nodes = Vec::new();
        let mut members = Vec::new();
        for (index, seed) in seeds.into_iter().enumerate() {
            let node = Arc::new(Mutex::new(Node::open(
                root.join(format!("node-{index}")),
                seed,
            )?));
            members.push(
                node.lock()
                    .map_err(lock_error)?
                    .member(format!("host-{index}")),
            );
            network.register(node.clone())?;
            nodes.push(Some(node));
        }
        let guild_id = *blake3::hash(&canonical_bytes(&members)?).as_bytes();
        Ok(Self {
            guild_id,
            members,
            nodes,
            network,
            directory,
        })
    }

    pub fn guild_id(&self) -> [u8; 32] {
        self.guild_id
    }

    pub fn node_id(&self, index: usize) -> NodeId {
        self.members[index].node_id
    }

    pub fn commit_source(&mut self, owner_index: usize, source: &Path) -> Result<QuorumCheckpoint> {
        let role_indices = role_indices(owner_index, self.nodes.len())?;
        let owner = self.live_node(role_indices[0])?;
        let revision =
            owner
                .lock()
                .map_err(lock_error)?
                .prepare_revision(self.guild_id, source, 1)?;
        let mut target_sectors = revision.value.metadata_sectors.clone();
        target_sectors.extend(revision.value.data_sectors.clone());
        let mut groups = Vec::with_capacity(target_sectors.len());

        for (ordinal, target_reference) in target_sectors.iter().enumerate() {
            let owner_bytes = owner
                .lock()
                .map_err(lock_error)?
                .sector(&target_reference.id)?;
            let (helper_a_reference, helper_a_bytes) = self
                .live_node(role_indices[1])?
                .lock()
                .map_err(lock_error)?
                .ensure_filler(
                    self.guild_id,
                    revision.value.revision_id,
                    ordinal as u64 * 2,
                )?;
            let (helper_b_reference, helper_b_bytes) = self
                .live_node(role_indices[2])?
                .lock()
                .map_err(lock_error)?
                .ensure_filler(
                    self.guild_id,
                    revision.value.revision_id,
                    ordinal as u64 * 2 + 1,
                )?;
            let shards = encode_3_2([owner_bytes, helper_a_bytes, helper_b_bytes])?;
            let group_id = group_id(
                self.guild_id,
                ordinal as u64,
                target_reference,
                &helper_a_reference,
                &helper_b_reference,
                self.members[role_indices[3]].node_id,
                self.members[role_indices[4]].node_id,
            )?;
            let parity_a = ParityObject {
                group_id,
                shard_index: 3,
                root: sector_root(&shards[3]),
                bytes: shards[3].clone(),
            };
            let parity_b = ParityObject {
                group_id,
                shard_index: 4,
                root: sector_root(&shards[4]),
                bytes: shards[4].clone(),
            };
            self.live_node(role_indices[3])?
                .lock()
                .map_err(lock_error)?
                .publish_parity(&parity_a)?;
            self.live_node(role_indices[4])?
                .lock()
                .map_err(lock_error)?
                .publish_parity(&parity_b)?;
            groups.push(CodingGroup {
                id: group_id,
                shard_size: V1_SECTOR_SIZE as u32,
                roles: [
                    ShardRole::Information(InformationRole {
                        owner: self.members[role_indices[0]].node_id,
                        sector: target_reference.clone(),
                    }),
                    ShardRole::Information(InformationRole {
                        owner: self.members[role_indices[1]].node_id,
                        sector: helper_a_reference,
                    }),
                    ShardRole::Information(InformationRole {
                        owner: self.members[role_indices[2]].node_id,
                        sector: helper_b_reference,
                    }),
                    ShardRole::Parity(ParityRole {
                        holder: self.members[role_indices[3]].node_id,
                        row: 0,
                        root: parity_a.root,
                    }),
                    ShardRole::Parity(ParityRole {
                        holder: self.members[role_indices[4]].node_id,
                        row: 1,
                        root: parity_b.root,
                    }),
                ],
            });
        }

        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 1,
                guild_id: self.guild_id,
                generation: 1,
                members: self.members.clone(),
                revisions: vec![revision],
                coding_groups: groups,
            },
            signatures: Vec::new(),
        };
        for node in self.nodes.iter().flatten() {
            checkpoint.add_signature(node.lock().map_err(lock_error)?.keys())?;
        }
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        for node in self.nodes.iter().flatten() {
            node.lock()
                .map_err(lock_error)?
                .store_checkpoint(&checkpoint)?;
        }
        self.publish_recovery_locators(owner_index, &checkpoint, checkpoint_hash)?;
        Ok(checkpoint)
    }

    pub fn lose_node(&mut self, index: usize) -> Result<PathBuf> {
        let node_id = self.members[index].node_id;
        self.network.remove(node_id)?;
        let node = self.nodes[index]
            .take()
            .context("node was already removed")?;
        let data_dir = node.lock().map_err(lock_error)?.data_dir().to_path_buf();
        drop(node);
        Ok(data_dir)
    }

    pub fn recover(
        &mut self,
        seed: Seed,
        data_dir: &Path,
        restore_target: &Path,
    ) -> Result<SharedNode> {
        let mut recovered = Node::open(data_dir, seed)?;
        let checkpoint = recover_checkpoint(recovered.keys(), &self.directory, &self.network)?;
        let revision = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == recovered.keys().node_id())
            .max_by_key(|revision| revision.value.sequence)
            .context("checkpoint contains no revision for recovering node")?;
        let ciphertexts = recover_owner_sectors(
            recovered.keys().node_id(),
            revision,
            &checkpoint,
            &self.network,
        )?;
        restore_revision(
            recovered.keys(),
            checkpoint.checkpoint.guild_id,
            revision,
            &ciphertexts,
            restore_target,
        )?;
        recovered.rebuild_from_checkpoint(&checkpoint)?;
        let recovered = Arc::new(Mutex::new(recovered));
        self.network.register(recovered.clone())?;
        Ok(recovered)
    }

    fn live_node(&self, index: usize) -> Result<SharedNode> {
        self.nodes[index].clone().context("node is offline")
    }

    fn publish_recovery_locators(
        &self,
        subject_index: usize,
        checkpoint: &QuorumCheckpoint,
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let subject = &self.members[subject_index];
        for node in self.nodes.iter().flatten() {
            let node = node.lock().map_err(lock_error)?;
            if node.keys().node_id() == subject.node_id {
                continue;
            }
            let locator = RecoveryLocator {
                format_version: 1,
                subject: subject.node_id,
                publisher: node.keys().node_id(),
                guild_id: self.guild_id,
                checkpoint_hash,
                checkpoint_generation: checkpoint.checkpoint.generation,
                endpoints: vec![format!("memory://{}", node.keys().node_id())],
                expires_at_unix_seconds: u64::MAX,
            };
            let signed =
                SignedRecord::sign(b"mutualbackup/recovery-locator/v1", locator, node.keys())?;
            let sealed =
                seal_recovery_record(subject.recovery_public_key, &canonical_bytes(&signed)?)?;
            self.directory
                .publish(subject.node_id, node.keys().node_id(), sealed)?;
        }
        Ok(())
    }
}

fn recover_checkpoint(
    keys: &KeyMaterial,
    directory: &MemoryDirectory,
    network: &MemoryNetwork,
) -> Result<QuorumCheckpoint> {
    let mut candidates = Vec::new();
    for sealed in directory.lookup(keys.node_id())? {
        let plaintext = match open_recovery_record(keys, &sealed) {
            Ok(plaintext) => plaintext,
            Err(_) => continue,
        };
        let signed: SignedRecord<RecoveryLocator> = match decode_canonical(&plaintext) {
            Ok(signed) => signed,
            Err(_) => continue,
        };
        if signed.verify(b"mutualbackup/recovery-locator/v1").is_err()
            || signed.signer != signed.value.publisher
            || signed.value.subject != keys.node_id()
            || signed.value.format_version != 1
        {
            continue;
        }
        let checkpoint =
            match network.checkpoint(signed.value.publisher, &signed.value.checkpoint_hash) {
                Ok(checkpoint) => checkpoint,
                Err(_) => continue,
            };
        if checkpoint.checkpoint.guild_id == signed.value.guild_id
            && checkpoint.checkpoint.generation == signed.value.checkpoint_generation
        {
            candidates.push(checkpoint);
        }
    }
    candidates
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.checkpoint.generation)
        .context("no valid recovery locator led to a quorum checkpoint")
}

fn recover_owner_sectors(
    owner: NodeId,
    revision: &SignedRecord<UserRevision>,
    checkpoint: &QuorumCheckpoint,
    network: &MemoryNetwork,
) -> Result<BTreeMap<SectorId, Vec<u8>>> {
    let wanted = revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .map(|reference| reference.id)
        .collect::<BTreeSet<_>>();
    let mut recovered = BTreeMap::new();
    for group in &checkpoint.checkpoint.coding_groups {
        let target_indices = group
            .roles
            .iter()
            .enumerate()
            .filter_map(|(index, role)| match role {
                ShardRole::Information(information)
                    if information.owner == owner && wanted.contains(&information.sector.id) =>
                {
                    Some((index, information.sector.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if target_indices.is_empty() {
            continue;
        }

        let mut shards = vec![None; 5];
        for (index, role) in group.roles.iter().enumerate() {
            let (holder, expected_root, result) = match role {
                ShardRole::Information(information) => (
                    information.owner,
                    information.sector.root,
                    network.sector(information.owner, &information.sector.id),
                ),
                ShardRole::Parity(parity) => (
                    parity.holder,
                    parity.root,
                    network.parity(parity.holder, &group.id, index as u8),
                ),
            };
            let _ = holder;
            match result {
                Ok(bytes)
                    if bytes.len() == group.shard_size as usize
                        && sector_root(&bytes) == expected_root =>
                {
                    shards[index] = Some(bytes);
                }
                _ => {}
            }
        }
        if shards.iter().filter(|shard| shard.is_some()).count() < 3 {
            bail!("coding group has fewer than three valid reachable shards");
        }
        reconstruct_3_2(&mut shards)?;
        for (index, reference) in target_indices {
            let bytes = shards[index]
                .take()
                .context("Reed--Solomon did not reconstruct the owner shard")?;
            if sector_root(&bytes) != reference.root {
                bail!("reconstructed owner sector failed its signed root");
            }
            recovered.insert(reference.id, bytes);
        }
    }
    if !wanted.iter().all(|id| recovered.contains_key(id)) {
        bail!("not all sectors referenced by the owner revision were recovered");
    }
    Ok(recovered)
}

fn role_indices(owner: usize, node_count: usize) -> Result<[usize; 5]> {
    if node_count != 5 || owner >= node_count {
        bail!("invalid node profile");
    }
    Ok([
        owner,
        (owner + 1) % 5,
        (owner + 2) % 5,
        (owner + 3) % 5,
        (owner + 4) % 5,
    ])
}

#[allow(clippy::too_many_arguments)]
fn group_id(
    guild_id: [u8; 32],
    ordinal: u64,
    owner: &SectorRef,
    helper_a: &SectorRef,
    helper_b: &SectorRef,
    parity_a: NodeId,
    parity_b: NodeId,
) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&canonical_bytes(&(
        guild_id, ordinal, owner, helper_a, helper_b, parity_a, parity_b,
    ))?)
    .as_bytes())
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("node state lock was poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run with MUTUALBACKUP_REFLINK_TEST_ROOT pointing at a disposable Btrfs
    /// or XFS directory. The GCP runner supplies that directory explicitly.
    #[test]
    fn seed_only_recovery_over_five_active_nodes() {
        let Some(test_root) = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") else {
            eprintln!("skipped: MUTUALBACKUP_REFLINK_TEST_ROOT is not set");
            return;
        };
        let root = PathBuf::from(test_root).join(format!("run-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("docs")).unwrap();
        fs::write(
            source.join("docs/readme.txt"),
            b"seed-only recovery works\n",
        )
        .unwrap();
        let large = (0..180_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(source.join("large.bin"), &large).unwrap();

        let seeds = (0_u8..5)
            .map(|value| Seed::from_bytes([value + 20; 32]))
            .collect::<Vec<_>>();
        let mut guild = PrototypeGuild::create(&root.join("nodes"), seeds).unwrap();
        guild.commit_source(0, &source).unwrap();
        let lost_data_dir = guild.lose_node(0).unwrap();
        let second_lost_data_dir = guild.lose_node(1).unwrap();
        fs::remove_dir_all(&lost_data_dir).unwrap();
        fs::remove_dir_all(&second_lost_data_dir).unwrap();
        fs::remove_dir_all(&source).unwrap();

        let restored = root.join("restored");
        guild
            .recover(
                Seed::from_bytes([20; 32]),
                &root.join("recovered-node"),
                &restored,
            )
            .unwrap();
        assert_eq!(
            fs::read(restored.join("docs/readme.txt")).unwrap(),
            b"seed-only recovery works\n"
        );
        assert_eq!(fs::read(restored.join("large.bin")).unwrap(), large);
        fs::remove_dir_all(&root).unwrap();
    }
}
