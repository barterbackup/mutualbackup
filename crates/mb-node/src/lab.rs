use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use mb_core::{
    CodingGroup, GuildCheckpoint, InformationRole, KeyMaterial, Member, NodeId, ParityRole,
    QuorumCheckpoint, RecoveryLocator, SectorId, Seed, ShardRole, SignedRecord, V1_RS_DATA_SHARDS,
    V1_RS_PARITY_SHARDS, V1_SECTOR_SIZE, canonical_bytes, decode_canonical, encode_3_2,
    open_recovery_record, reconstruct_3_2, seal_recovery_record, sector_root,
};
use mb_store::ParityObject;

use crate::{Node, RecoveredShards};

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

    pub fn lookup(&self, subject: NodeId) -> Result<Vec<(NodeId, mb_core::SealedRecoveryRecord)>> {
        Ok(self
            .records
            .lock()
            .map_err(lock_error)?
            .get(&subject)
            .map(|publishers| {
                publishers
                    .iter()
                    .map(|(publisher, record)| (*publisher, record.clone()))
                    .collect()
            })
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
            let failure_domain = format!("host-{index}");
            let mut opened = Node::open(root.join(format!("node-{index}")), seed)?;
            opened.configure_failure_domain(&failure_domain)?;
            members.push(opened.member(failure_domain));
            let node = Arc::new(Mutex::new(opened));
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
                .prepare_revision(self.guild_id, source, 1, None)?;
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
            let roles = [
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
                    root: sector_root(&shards[3]),
                }),
                ShardRole::Parity(ParityRole {
                    holder: self.members[role_indices[4]].node_id,
                    row: 1,
                    root: sector_root(&shards[4]),
                }),
            ];
            let mut group = CodingGroup {
                id: [0; 32],
                format_version: 1,
                guild_id: self.guild_id,
                data_shards: V1_RS_DATA_SHARDS,
                parity_shards: V1_RS_PARITY_SHARDS,
                shard_size: V1_SECTOR_SIZE as u32,
                roles,
            };
            group.id = group.calculate_id()?;
            let group_id = group.id;
            let parity_a = ParityObject {
                format_version: 1,
                guild_id: self.guild_id,
                group_id,
                shard_index: 3,
                root: sector_root(&shards[3]),
                bytes: shards[3].clone(),
            };
            let parity_b = ParityObject {
                format_version: 1,
                guild_id: self.guild_id,
                group_id,
                shard_index: 4,
                root: sector_root(&shards[4]),
                bytes: shards[4].clone(),
            };
            let information = [shards[0].clone(), shards[1].clone(), shards[2].clone()];
            self.live_node(role_indices[3])?
                .lock()
                .map_err(lock_error)?
                .publish_verified_parity(&group, &information, &parity_a)?;
            self.live_node(role_indices[4])?
                .lock()
                .map_err(lock_error)?
                .publish_verified_parity(&group, &information, &parity_b)?;
            groups.push(group);
        }

        groups.sort_by_key(|group| group.id);
        let mut checkpoint_members = self.members.clone();
        checkpoint_members.sort_by_key(|member| member.node_id);

        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 1,
                guild_id: self.guild_id,
                generation: 1,
                parent: None,
                members: checkpoint_members,
                revisions: vec![revision],
                coding_groups: groups,
            },
            signatures: Vec::new(),
        };
        for node in self.nodes.iter().flatten() {
            let signature = node
                .lock()
                .map_err(lock_error)?
                .sign_checkpoint(&checkpoint.checkpoint)?;
            checkpoint.signatures.push(signature);
        }
        checkpoint
            .signatures
            .sort_by_key(|signature| signature.signer);
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        for node in self.nodes.iter().flatten() {
            node.lock()
                .map_err(lock_error)?
                .store_checkpoint(&checkpoint)?;
        }
        for subject_index in 0..self.members.len() {
            self.publish_recovery_locators(subject_index, &checkpoint, checkpoint_hash)?;
        }
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
        let recovered_shards =
            recover_local_shards(recovered.keys().node_id(), &checkpoint, &self.network)?;
        let checkpoint_hash = checkpoint.hash()?;
        for ((group_id, shard_index), bytes) in &recovered_shards {
            let group = checkpoint
                .checkpoint
                .coding_groups
                .binary_search_by_key(group_id, |group| group.id)
                .ok()
                .map(|index| &checkpoint.checkpoint.coding_groups[index])
                .context("recovered unknown coding group")?;
            recovered.stage_recovered_shard(
                &checkpoint_hash,
                &checkpoint.checkpoint.guild_id,
                group,
                *shard_index,
                bytes,
            )?;
        }
        recovered.install_recovered_checkpoint(&checkpoint)?;
        drop(recovered_shards);
        let revision = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == recovered.keys().node_id())
            .max_by_key(|revision| revision.value.sequence);
        if let Some(revision) = revision {
            recovered.restore_recovered_revision(
                &checkpoint_hash,
                checkpoint.checkpoint.guild_id,
                revision,
                restore_target,
            )?;
        }
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
    for (published_by, sealed) in directory.lookup(keys.node_id())? {
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
            || signed.value.publisher != published_by
            || signed.value.subject != keys.node_id()
            || signed.value.format_version != 1
            || signed.value.expires_at_unix_seconds != u64::MAX
        {
            continue;
        }
        let checkpoint =
            match network.checkpoint(signed.value.publisher, &signed.value.checkpoint_hash) {
                Ok(checkpoint) => checkpoint,
                Err(_) => continue,
            };
        if checkpoint
            .validate_recovery_authority(keys, &signed.value, published_by)
            .is_ok()
        {
            candidates.push(checkpoint);
        }
    }
    candidates
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.checkpoint.generation)
        .context("no valid recovery locator led to a quorum checkpoint")
}

fn recover_local_shards(
    recovering: NodeId,
    checkpoint: &QuorumCheckpoint,
    network: &MemoryNetwork,
) -> Result<RecoveredShards> {
    let mut recovered = BTreeMap::new();
    for group in &checkpoint.checkpoint.coding_groups {
        let target = group
            .roles
            .iter()
            .enumerate()
            .find_map(|(index, role)| match role {
                ShardRole::Information(information) if information.owner == recovering => {
                    Some((index, information.sector.root))
                }
                ShardRole::Parity(parity) if parity.holder == recovering => {
                    Some((index, parity.root))
                }
                _ => None,
            });
        let Some((target_index, target_root)) = target else {
            continue;
        };

        let mut shards = vec![None; 5];
        for (index, role) in group.roles.iter().enumerate() {
            if index == target_index {
                continue;
            }
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
        let bytes = shards[target_index]
            .take()
            .context("Reed--Solomon did not reconstruct the local shard")?;
        if sector_root(&bytes) != target_root {
            bail!("reconstructed local shard failed its signed root");
        }
        recovered.insert((group.id, target_index as u8), bytes);
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

fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("node state lock was poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run with MUTUALBACKUP_REFLINK_TEST_ROOT pointing at a disposable Btrfs
    /// or XFS directory. The GCP runner supplies that directory explicitly.
    #[test]
    #[ignore = "requires an explicitly provisioned reflink test filesystem"]
    fn seed_only_recovery_over_five_active_nodes() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
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

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::PermissionsExt;

            let unsupported = source.join("unsupported-fifo");
            let name = CString::new(unsupported.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

            let seeds = (0_u8..5)
                .map(|value| Seed::from_bytes([value + 70; 32]))
                .collect::<Vec<_>>();
            let mut rejecting_guild =
                PrototypeGuild::create(&root.join("rejecting-nodes"), seeds).unwrap();
            assert!(rejecting_guild.commit_source(0, &source).is_err());
            fs::remove_file(unsupported).unwrap();

            fs::set_permissions(
                source.join("docs/readme.txt"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o751)).unwrap();
            filetime::set_file_mtime(
                source.join("docs/readme.txt"),
                filetime::FileTime::from_unix_time(1_700_000_001, 123_456_789),
            )
            .unwrap();
            filetime::set_file_mtime(
                &source,
                filetime::FileTime::from_unix_time(1_700_000_002, 987_654_321),
            )
            .unwrap();
        }

        let seeds = (0_u8..5)
            .map(|value| Seed::from_bytes([value + 20; 32]))
            .collect::<Vec<_>>();
        let mut guild = PrototypeGuild::create(&root.join("nodes"), seeds).unwrap();
        let checkpoint = guild.commit_source(0, &source).unwrap();
        let mut fork = checkpoint.checkpoint.clone();
        let group = &mut fork.coding_groups[0];
        let ShardRole::Parity(parity) = &mut group.roles[3] else {
            unreachable!();
        };
        parity.root[0] ^= 1;
        group.id = group.calculate_id().unwrap();
        fork.coding_groups.sort_by_key(|group| group.id);
        assert!(
            guild.nodes[0]
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .sign_checkpoint(&fork)
                .is_err()
        );
        fs::remove_dir_all(&source).unwrap();

        for index in 0..5 {
            let lost_data_dir = guild.lose_node(index).unwrap();
            fs::remove_dir_all(&lost_data_dir).unwrap();
            let restored = root.join(format!("restored-{index}"));
            let recovered = guild
                .recover(
                    Seed::from_bytes([20 + index as u8; 32]),
                    &root.join(format!("recovered-node-{index}")),
                    &restored,
                )
                .unwrap();
            if index == 0 {
                assert_eq!(
                    fs::read(restored.join("docs/readme.txt")).unwrap(),
                    b"seed-only recovery works\n"
                );
                assert_eq!(fs::read(restored.join("large.bin")).unwrap(), large);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};

                    let root_metadata = fs::metadata(&restored).unwrap();
                    assert_eq!(root_metadata.permissions().mode() & 0o7777, 0o751);
                    assert_eq!(root_metadata.mtime(), 1_700_000_002);
                    assert_eq!(root_metadata.mtime_nsec(), 987_654_321);
                    let file_metadata = fs::metadata(restored.join("docs/readme.txt")).unwrap();
                    assert_eq!(file_metadata.permissions().mode() & 0o7777, 0o640);
                    assert_eq!(file_metadata.mtime(), 1_700_000_001);
                    assert_eq!(file_metadata.mtime_nsec(), 123_456_789);
                }
            } else {
                assert!(!restored.exists());
            }

            let node_id = recovered.lock().unwrap().keys().node_id();
            let (group, role_index, role) = checkpoint
                .checkpoint
                .coding_groups
                .iter()
                .find_map(|group| {
                    group
                        .roles
                        .iter()
                        .enumerate()
                        .find(|(_, role)| match role {
                            ShardRole::Information(information) => information.owner == node_id,
                            ShardRole::Parity(parity) => parity.holder == node_id,
                        })
                        .map(|(role_index, role)| (group, role_index, role))
                })
                .unwrap();
            let bytes = match role {
                ShardRole::Information(information) => recovered
                    .lock()
                    .unwrap()
                    .sector(&information.sector.id)
                    .unwrap(),
                ShardRole::Parity(_) => recovered
                    .lock()
                    .unwrap()
                    .parity(&group.id, role_index as u8)
                    .unwrap(),
            };
            let expected = match role {
                ShardRole::Information(information) => information.sector.root,
                ShardRole::Parity(parity) => parity.root,
            };
            assert_eq!(sector_root(&bytes), expected);
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
