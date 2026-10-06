//! Explicit peer reads for historical export; original catalogs stay read-only.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use libp2p::Multiaddr;
use mb_core::{
    CodingGroup, CodingGroupV2, KeyMaterial, NodeId, SectorRef, Seed, ShardRole, ShardRoleV2,
    V1_SECTOR_SIZE, sector_root,
};

use super::LegacyExportReport;
use crate::{Node, P2pClient, P2pConfig, TorMode, build_p2p};

/// An explicitly selected identity-bound peer endpoint: `NODE-ID=MULTIADDR`.
#[derive(Clone, Debug)]
pub struct LegacyExportPeer {
    pub node_id: NodeId,
    pub address: Multiaddr,
}

impl FromStr for LegacyExportPeer {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (id, address) = value
            .split_once('=')
            .context("expected NODE-ID=MULTIADDR")?;
        let node_id = id.parse()?;
        let address = crate::network::validate_published_endpoint(node_id, address)?;
        Ok(Self { node_id, address })
    }
}

pub(super) struct PeerRecovery {
    pub(super) client: P2pClient,
    pub(super) runtime: tokio::runtime::Handle,
    pub(super) peers: BTreeSet<NodeId>,
}

fn scratch_parent(
    candidate: &Path,
    data_dir: &Path,
    anchor_areas: &[PathBuf],
    parity_volumes: &[PathBuf],
) -> Result<PathBuf> {
    let parent = candidate.canonicalize()?;
    for input in std::iter::once(data_dir)
        .chain(anchor_areas.iter().map(PathBuf::as_path))
        .chain(parity_volumes.iter().map(PathBuf::as_path))
    {
        ensure!(
            !parent.starts_with(input.canonicalize()?),
            "temporary client directory must be outside preserved inputs; select another TMPDIR"
        );
    }
    Ok(parent)
}

impl PeerRecovery {
    fn read<T>(&self, future: impl std::future::Future<Output = Result<T>>) -> Option<T> {
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), future)
                .await
                .ok()?
                .ok()
        })
    }

    pub(super) fn sector(&self, guild: [u8; 32], reference: &SectorRef) -> Option<Vec<u8>> {
        for peer in &self.peers {
            if let Some(bytes) = self.read(self.client.sector(*peer, guild, reference.id))
                && bytes.len() == V1_SECTOR_SIZE
                && sector_root(&bytes) == reference.root
            {
                return Some(bytes);
            }
        }
        None
    }

    pub(super) fn fixed(
        &self,
        group: &CodingGroup,
        index: usize,
        assigned_only: bool,
    ) -> Option<Vec<u8>> {
        let (holder, root) = match &group.roles[index] {
            ShardRole::Information(info) => (info.owner, info.sector.root),
            ShardRole::Parity(parity) => (parity.holder, parity.root),
        };
        let peers = std::iter::once(holder)
            .chain(self.peers.iter().copied().filter(|peer| *peer != holder));
        for peer in peers.filter(|peer| self.peers.contains(peer)) {
            if assigned_only && peer != holder {
                continue;
            }
            if let ShardRole::Information(info) = &group.roles[index]
                && let Some(bytes) =
                    self.read(self.client.sector(peer, group.guild_id, info.sector.id))
                && bytes.len() == V1_SECTOR_SIZE
                && sector_root(&bytes) == root
            {
                return Some(bytes);
            }
            if let Some(bytes) =
                self.read(
                    self.client
                        .parity(peer, group.guild_id, group.id, index as u8),
                )
                && bytes.len() == V1_SECTOR_SIZE
                && sector_root(&bytes) == root
            {
                return Some(bytes);
            }
        }
        None
    }

    pub(super) fn variable(
        &self,
        group: &CodingGroupV2,
        index: usize,
        assigned_only: bool,
    ) -> Option<Vec<u8>> {
        let holder = match &group.roles[index] {
            ShardRoleV2::Information(info) => info.owner,
            ShardRoleV2::Parity(parity) => parity.holder,
        };
        if self.peers.contains(&holder)
            && let Some(bytes) = self.read(self.client.variable_shard(holder, group, index as u16))
        {
            return Some(bytes);
        }
        if assigned_only {
            return None;
        }
        for peer in &self.peers {
            if let Some(bytes) = self.read(self.client.variable_emergency_shard(
                *peer,
                group,
                index as u16,
            )) {
                return Some(bytes);
            }
        }
        None
    }
}

/// Recover from explicitly selected peers using a separate temporary client.
/// Only read requests are issued; no publication, repair, enrollment or retirement.
pub async fn export_withdrawn_revision_from_catalog_over_network(
    seed: Seed,
    data_dir: PathBuf,
    revision_id: uuid::Uuid,
    target: PathBuf,
    anchor_areas: Vec<PathBuf>,
    parity_volumes: Vec<PathBuf>,
    peers: Vec<LegacyExportPeer>,
) -> Result<LegacyExportReport> {
    ensure!(
        !peers.is_empty() && peers.len() <= 64,
        "select between one and 64 peer endpoints"
    );
    let keys = KeyMaterial::from_seed(&seed);
    for peer in &peers {
        crate::network::validate_published_endpoint(peer.node_id, &peer.address.to_string())?;
        ensure!(
            peer.node_id != keys.node_id(),
            "select surviving peers, not the recovering identity"
        );
    }
    let parent = scratch_parent(
        &std::env::temp_dir(),
        &data_dir,
        &anchor_areas,
        &parity_volumes,
    )?;
    let scratch = tempfile::Builder::new()
        .prefix("mutualbackup-legacy-peer-client-")
        .tempdir_in(parent)?;
    let node_path = scratch.path().to_path_buf();
    let node = tokio::task::spawn_blocking(move || Node::open(node_path, seed)).await??;
    let node = Arc::new(Mutex::new(node));
    let (client, mut event_loop) = build_p2p(
        node.clone(),
        P2pConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse()?],
            external_addresses: vec![],
            bootstrap_addresses: vec![],
            relay_reservation_addresses: vec![],
            enable_dht_maintenance: false,
            enable_relay_server: false,
            enable_hole_punching: false,
            enable_port_mapping: false,
            public_endpoint: String::new(),
            failure_domain: String::new(),
            configure_failure_domain: false,
            max_connections: 8,
            tor_mode: TorMode::DisableTor,
        },
    )?;
    let startup = event_loop.take_startup_receiver()?;
    let task = tokio::spawn(event_loop.run());
    let recovery_client = client.clone();
    let result = async {
        startup
            .await
            .context("temporary recovery client stopped during startup")?
            .map_err(anyhow::Error::msg)?;
        let mut selected = BTreeSet::new();
        for peer in peers {
            selected.insert(peer.node_id);
            client.add_peer_address(peer.node_id, peer.address).await?;
        }
        let remote = PeerRecovery {
            client: recovery_client,
            runtime: tokio::runtime::Handle::current(),
            peers: selected,
        };
        tokio::task::spawn_blocking(move || {
            super::export_catalog(
                &keys,
                &data_dir,
                revision_id,
                &target,
                &anchor_areas,
                &parity_volumes,
                Some(&remote),
            )
        })
        .await
        .context("legacy peer export worker failed")?
    }
    .await;
    // Finish the isolated transport before removing its private scratch state,
    // including on an export failure. Original state is never opened by Node.
    let shutdown = client.shutdown().await;
    let stopped = task.await.context("temporary recovery client failed");
    drop(client);
    drop(node);
    if let Err(error) = scratch.close() {
        tracing::warn!(%error, "temporary recovery client cleanup failed");
    }
    if let Err(error) = shutdown {
        tracing::warn!(%error, "temporary recovery client shutdown failed");
    }
    if !matches!(stopped, Ok(Ok(()))) {
        tracing::warn!(?stopped, "temporary recovery client stopped with an error");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_export_peer_scratch_rejects_preserved_inputs_before_creation() {
        let temp = tempfile::tempdir().unwrap();
        let paths: Vec<_> = ["catalog", "anchors", "parity"]
            .into_iter()
            .map(|name| temp.path().join(name))
            .collect();
        for path in &paths {
            std::fs::create_dir(path).unwrap();
        }
        assert!(scratch_parent(temp.path(), &paths[0], &paths[1..2], &paths[2..]).is_ok());
        for path in &paths {
            assert!(scratch_parent(path, &paths[0], &paths[1..2], &paths[2..]).is_err());
            assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
        }
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&paths[0], &alias).unwrap();
        assert!(scratch_parent(&alias, &paths[0], &paths[1..2], &paths[2..]).is_err());
        let first = KeyMaterial::from_seed(&Seed::from_bytes([71; 32])).node_id();
        let second = KeyMaterial::from_seed(&Seed::from_bytes([72; 32])).node_id();
        assert!(
            format!(
                "{first}=/ip4/127.0.0.1/udp/9/quic-v1/p2p/{}",
                second.libp2p_peer_id().unwrap()
            )
            .parse::<LegacyExportPeer>()
            .is_err()
        );
    }
}
