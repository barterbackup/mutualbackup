//! Explicit peer reads for historical export; original catalogs stay read-only.

use std::{
    collections::BTreeSet,
    os::unix::fs::MetadataExt,
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
use mb_store::ControlStore;

use super::LegacyExportReport;
use super::local_inventory::PreservedInputScope;
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

/// Explicit survivors and identity-bound Kademlia bootstrap endpoints. Bootstrap
/// peers are queried for directory data; they are not automatically survivors.
#[derive(Clone, Debug, Default)]
pub struct LegacyPeerSources {
    pub peers: Vec<LegacyExportPeer>,
    pub bootstrap_peers: Vec<LegacyExportPeer>,
}

impl From<Vec<LegacyExportPeer>> for LegacyPeerSources {
    fn from(peers: Vec<LegacyExportPeer>) -> Self {
        Self {
            peers,
            bootstrap_peers: vec![],
        }
    }
}

pub(super) struct PeerRecovery {
    pub(super) client: P2pClient,
    pub(super) runtime: tokio::runtime::Handle,
    pub(super) peers: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LegacyPeerInventoryCoverage {
    pub selected_peers: u64,
    pub verified_checkpoints: u64,
    pub unavailable_heads: u64,
    pub unavailable_parent_links: u64,
    pub unauthorized_owner_checkpoints: u64,
}

fn scratch_parent(
    candidate: &Path,
    data_dir: &Path,
    anchor_areas: &[PathBuf],
    parity_volumes: &[PathBuf],
    scope: &PreservedInputScope,
) -> Result<PathBuf> {
    scratch_parent_with_native_lookup(
        candidate,
        data_dir,
        anchor_areas,
        parity_volumes,
        scope,
        |path| mb_store::directory_identity(path),
    )
}

fn scratch_parent_with_native_lookup(
    candidate: &Path,
    data_dir: &Path,
    anchor_areas: &[PathBuf],
    parity_volumes: &[PathBuf],
    scope: &PreservedInputScope,
    native_identity: impl Fn(
        &Path,
    ) -> std::result::Result<mb_store::NativeFileId, mb_store::AnchorError>,
) -> Result<PathBuf> {
    let parent = candidate.canonicalize()?;
    let mut directory_ids = BTreeSet::new();
    let native_inodes: BTreeSet<_> = scope.native_roots.iter().map(|id| id.inode).collect();
    for input in std::iter::once(data_dir)
        .chain(anchor_areas.iter().map(PathBuf::as_path))
        .chain(parity_volumes.iter().map(PathBuf::as_path))
    {
        let input = input.canonicalize()?;
        reject_preserved_parent(&parent, &input)?;
        let metadata = input.metadata()?;
        if metadata.is_dir() {
            directory_ids.insert((metadata.dev(), metadata.ino()));
        }
    }
    for input in &scope.paths {
        match input.canonicalize() {
            Ok(input) => {
                reject_preserved_parent(&parent, &input)?;
                let metadata = input.metadata()?;
                if metadata.is_dir() {
                    directory_ids.insert((metadata.dev(), metadata.ino()));
                }
            }
            // Recovery need not have the original sources or anchor locations.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error).context("cannot inspect preserved input location"),
        }
    }
    for ancestor in parent.ancestors() {
        let metadata = ancestor.metadata()?;
        ensure!(
            !directory_ids.contains(&(metadata.dev(), metadata.ino())),
            "temporary client directory must be outside preserved inputs; select another TMPDIR"
        );
        if native_inodes.contains(&metadata.ino()) {
            // Only possible inode matches need a stable filesystem lookup.
            // If it is unavailable, a renamed preserved root cannot be ruled
            // out, including after a kernel/filesystem capability change.
            let identity = native_identity(ancestor).context(
                "cannot verify temporary client directory ancestry; select another TMPDIR",
            )?;
            ensure!(
                !scope.native_roots.contains(&identity),
                "temporary client directory must be outside preserved inputs; select another TMPDIR"
            );
        }
    }
    Ok(parent)
}

fn reject_preserved_parent(parent: &Path, input: &Path) -> Result<()> {
    ensure!(
        !parent.starts_with(input),
        "temporary client directory must be outside preserved inputs; select another TMPDIR"
    );
    Ok(())
}

fn peer_client_preflight(
    keys: &KeyMaterial,
    data_dir: &Path,
    candidate: &Path,
    protected_inputs: &[PathBuf],
    discover: bool,
) -> Result<(PathBuf, Option<[u8; 32]>)> {
    crate::volume::with_inspected_control_snapshot(data_dir, keys, |control| {
        let (local_state, scope) = super::local_inventory::collect_with_scope(
            control,
            &mut 0,
            mb_core::V1_MAX_CATALOG_BYTES,
        )?;
        mb_core::canonical_size_bounded(&local_state, mb_core::V1_MAX_CATALOG_BYTES)?;
        drop(local_state);
        let guild = if discover {
            Some(
                crate::node::preserved_guild_certificate(control)?
                    .context("directory discovery requires the preserved signed guild certificate")?
                    .genesis
                    .guild_id,
            )
        } else {
            None
        };
        Ok((
            scratch_parent(candidate, data_dir, protected_inputs, &[], &scope)?,
            guild,
        ))
    })
}

impl PeerRecovery {
    fn read<T>(&self, future: impl std::future::Future<Output = Result<T>>) -> Option<T> {
        self.try_read(future).ok()
    }

    fn try_read<T>(&self, future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), future)
                .await
                .context("selected legacy peer read timed out")?
        })
    }

    pub(super) fn checkpoints(
        &self,
        guild: [u8; 32],
        origin: Option<[u8; 32]>,
        mut visit: impl FnMut(mb_core::QuorumCheckpoint) -> Result<bool>,
    ) -> Result<LegacyPeerInventoryCoverage> {
        // Check every available head before searching history. A peer's long
        // history must not hide a usable current certificate on another peer.
        let mut coverage = LegacyPeerInventoryCoverage {
            selected_peers: self.peers.len() as u64,
            ..Default::default()
        };
        let mut parents = Vec::new();
        for peer in &self.peers {
            let Some(Some((generation, hash))) =
                self.read(self.client.preserved_checkpoint_head(*peer, guild))
            else {
                coverage.unavailable_heads += 1;
                continue;
            };
            let Some(checkpoint) = self.checkpoint(*peer, guild, origin, generation, hash) else {
                coverage.unavailable_heads += 1;
                continue;
            };
            let parent = checkpoint.checkpoint.parent.map(|hash| {
                (
                    *peer,
                    checkpoint.checkpoint.genesis_hash,
                    generation - 1,
                    hash,
                )
            });
            coverage.verified_checkpoints += 1;
            ensure!(
                coverage.verified_checkpoints <= 1_000_000,
                "selected peer checkpoint history exceeds the recovery work bound"
            );
            if !visit(checkpoint)? {
                return Ok(coverage);
            }
            parents.extend(parent);
        }
        // Each signed link commits to the parent's hash. Exact decreasing
        // generations prevent loops without retaining a history-sized hash set.
        // Keep only the bounded head cursors and one decoded certificate.
        for (mut source, origin, mut generation, mut hash) in parents {
            loop {
                let candidate = std::iter::once(source)
                    .chain(self.peers.iter().copied().filter(|peer| *peer != source))
                    .find_map(|peer| {
                        self.checkpoint(peer, guild, Some(origin), generation, hash)
                            .map(|checkpoint| (peer, checkpoint))
                    });
                let Some((peer, checkpoint)) = candidate else {
                    coverage.unavailable_parent_links += 1;
                    break;
                };
                let parent = checkpoint.checkpoint.parent;
                coverage.verified_checkpoints += 1;
                ensure!(
                    coverage.verified_checkpoints <= 1_000_000,
                    "selected peer checkpoint history exceeds the recovery work bound"
                );
                if !visit(checkpoint)? {
                    return Ok(coverage);
                }
                let Some(parent) = parent else {
                    break;
                };
                source = peer;
                generation -= 1;
                hash = parent;
            }
        }
        Ok(coverage)
    }

    fn checkpoint(
        &self,
        peer: NodeId,
        guild: [u8; 32],
        origin: Option<[u8; 32]>,
        generation: u64,
        hash: [u8; 32],
    ) -> Option<mb_core::QuorumCheckpoint> {
        let checkpoint = self.read(crate::network::fetch_p2p_checkpoint(
            &self.client,
            peer,
            guild,
            hash,
        ))?;
        (checkpoint.checkpoint.guild_id == guild
            && checkpoint.checkpoint.generation == generation
            && origin.is_none_or(|hash| checkpoint.checkpoint.genesis_hash == hash))
        .then_some(checkpoint)
    }

    pub(super) fn transcripts(
        &self,
        control: &ControlStore,
        checkpoint: &mb_core::QuorumCheckpoint,
        descriptor: &mb_core::PackedSectorDescriptor,
        mut visit: impl FnMut(
            mb_core::SignedRecord<mb_core::CodingVerificationTranscript>,
        ) -> Result<bool>,
    ) -> Result<()> {
        let Some(genesis) = crate::node::preserved_guild_certificate(control)? else {
            return Ok(());
        };
        let guild = checkpoint.checkpoint.guild_id;
        ensure!(
            genesis.genesis.guild_id == guild
                && genesis.hash()? == checkpoint.checkpoint.genesis_hash,
            "preserved guild certificate conflicts with the packed checkpoint"
        );
        let mut evidence_error = None;
        let mut recovered = false;
        let result = self.replay_events(genesis, |state, event| {
            let Some(event) = event else { return Ok(true); };
            if let Some((group, expected_hash)) = event.event.kind.coding_group_add()
                && group.roles.iter().any(|role| matches!(role,
                    ShardRoleV2::Information(info) if info.sector.id == descriptor.id
                        && info.sector.commitment == descriptor.commitment && !info.sector.virtual_zero)) {
                let event_hash = event.event.hash()?;
                for source in &self.peers {
                    let transcript = match self.try_read(self.client.coding_transcript_for_event(
                        *source, guild, group.id, event.event.sequence, event_hash,
                    )) {
                        Ok(transcript) => transcript,
                        Err(error) => { evidence_error = Some(error); continue; }
                    };
                    let hash = transcript.canonical_hash()?;
                    let transcript = transcript.into_inner();
                    if transcript.value.manifest.value.group != *group {
                        evidence_error = Some(anyhow::anyhow!("coding transcript conflicts with its certified group"));
                        continue;
                    }
                    if let Err(error) = state.validate_attempt_authority(&transcript.value.plan.value) {
                        evidence_error = Some(anyhow::Error::from(error).context("coding Add transcript has invalid attempt authority"));
                        continue;
                    }
                    let bound = if let Some(expected) = expected_hash { expected == hash }
                        else {
                            self.peers.iter().any(|source| {
                                self.read(self.client.legacy_coding_add_binding(*source, guild, event.event.sequence, event_hash))
                                    .flatten().is_some_and(|binding| binding.statement.transcript_hash == hash
                                        && binding.verify(state, event).is_ok())
                            })
                        };
                    if !bound {
                        evidence_error = Some(anyhow::anyhow!("coding Add lacks its exact transcript hash or preissued quorum binding"));
                        continue;
                    }
                    if !visit(transcript)? { recovered = true; return Ok(false); }
                }
            }
            Ok(true)
        });
        if recovered {
            return result;
        }
        if let Some(error) = evidence_error {
            result?;
            return Err(error).context("selected peers cannot provide certified coding evidence");
        }
        result
    }

    fn replay_events(
        &self,
        genesis: mb_core::QuorumGuildGenesis,
        mut visit: impl FnMut(
            &mb_core::DynamicGuildState,
            Option<&mb_core::QuorumGuildEvent>,
        ) -> Result<bool>,
    ) -> Result<()> {
        let guild = genesis.genesis.guild_id;
        let mut state = mb_core::DynamicGuildState::new(
            guild,
            genesis.hash()?,
            mb_core::QuorumPolicy {
                format_version: 1,
                rule: mb_core::QuorumRule::Unanimous,
            },
            genesis.genesis.members,
        )?;
        if !visit(&state, None)? {
            return Ok(());
        }
        loop {
            let mut advanced = false;
            let mut last_error = None;
            for peer in &self.peers {
                let tail = match self.try_read(self.client.guild_event_tail(
                    *peer,
                    guild,
                    state.event_sequence,
                    state.event_head,
                )) {
                    Ok(tail) => tail,
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                };
                if tail.events.is_empty() {
                    continue;
                }
                // Validate the complete page before using its Add events. Do
                // not retain an event-history vector or install replayed state.
                let mut checked = state.clone();
                if let Err(error) = checked.apply_tail(&tail) {
                    last_error = Some(error.into());
                    continue;
                }
                if mb_core::canonical_size_bounded(&checked, mb_core::V1_MAX_CATALOG_BYTES).is_err()
                    || checked.event_sequence > 1_000_000
                {
                    continue;
                }
                drop(checked);
                for event in tail.events {
                    if !visit(&state, Some(&event))? {
                        return Ok(());
                    }
                    state.apply_event(&event)?;
                    if !visit(&state, None)? {
                        return Ok(());
                    }
                }
                advanced = true;
                break;
            }
            if !advanced {
                if let Some(error) = last_error {
                    return Err(error).context(
                        "selected peers cannot provide authenticated guild event history",
                    );
                }
                return Ok(());
            }
        }
    }

    pub(super) fn find_revision(
        &self,
        control: &ControlStore,
        owner: NodeId,
        revision_id: uuid::Uuid,
    ) -> Result<Option<mb_core::QuorumCheckpoint>> {
        let Some(certificate) = crate::node::preserved_guild_certificate(control)? else {
            return Ok(None);
        };
        let mut found = None;
        self.checkpoints(
            certificate.genesis.guild_id,
            Some(certificate.hash()?),
            |checkpoint| {
                if checkpoint.checkpoint.revisions.iter().any(|revision| {
                    revision.value.owner == owner && revision.value.revision_id == revision_id
                }) {
                    let authorized =
                        self.authorizes_checkpoint(&certificate, owner, &checkpoint)?;
                    if authorized {
                        found = Some(checkpoint);
                    }
                    Ok(!authorized)
                } else {
                    Ok(true)
                }
            },
        )?;
        Ok(found)
    }

    pub(super) fn authorizes_checkpoint(
        &self,
        certificate: &mb_core::QuorumGuildGenesis,
        owner: NodeId,
        checkpoint: &mb_core::QuorumCheckpoint,
    ) -> Result<bool> {
        ensure!(
            checkpoint.checkpoint.guild_id == certificate.genesis.guild_id
                && checkpoint.checkpoint.genesis_hash == certificate.hash()?,
            "selected peer checkpoint conflicts with the preserved genesis"
        );
        let mut authorized = certificate
            .genesis
            .members
            .iter()
            .any(|member| member.node_id == owner);
        if !authorized {
            self.replay_events(certificate.clone(), |state, _| {
                authorized = state
                    .members
                    .iter()
                    .any(|member| member.member.node_id == owner)
                    && crate::node::checkpoint_matches_dynamic_authority(
                        &checkpoint.checkpoint,
                        state,
                    );
                Ok(!authorized)
            })?;
        }
        Ok(authorized)
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
    peers: impl Into<LegacyPeerSources>,
) -> Result<LegacyExportReport> {
    let protected_inputs = anchor_areas
        .iter()
        .chain(&parity_volumes)
        .cloned()
        .collect();
    with_peer_recovery(
        seed,
        data_dir,
        protected_inputs,
        peers.into(),
        move |keys, data_dir, remote| {
            super::export_catalog(
                &keys,
                &data_dir,
                revision_id,
                &target,
                &anchor_areas,
                &parity_volumes,
                Some(&remote),
            )
        },
    )
    .await
}

pub(super) async fn with_peer_recovery<T: Send + 'static>(
    seed: Seed,
    data_dir: PathBuf,
    protected_inputs: Vec<PathBuf>,
    sources: LegacyPeerSources,
    operation: impl FnOnce(KeyMaterial, PathBuf, PeerRecovery) -> Result<T> + Send + 'static,
) -> Result<T> {
    ensure!(
        (!sources.peers.is_empty() || !sources.bootstrap_peers.is_empty())
            && sources.peers.len() <= 64
            && sources.bootstrap_peers.len() <= 64,
        "select one to 64 survivor or bootstrap endpoints per source"
    );
    let keys = KeyMaterial::from_seed(&seed);
    for peer in sources.peers.iter().chain(&sources.bootstrap_peers) {
        crate::network::validate_published_endpoint(peer.node_id, &peer.address.to_string())?;
        ensure!(
            peer.node_id != keys.node_id(),
            "select surviving peers, not the recovering identity"
        );
    }
    let (parent, discovery_guild) = {
        let preserved = data_dir.clone();
        let original_seed = seed.clone();
        let candidate = std::env::temp_dir();
        let discover = !sources.bootstrap_peers.is_empty();
        tokio::task::spawn_blocking(move || {
            let keys = KeyMaterial::from_seed(&original_seed);
            peer_client_preflight(&keys, &preserved, &candidate, &protected_inputs, discover)
        })
        .await??
    };
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
            bootstrap_addresses: sources
                .bootstrap_peers
                .iter()
                .map(|peer| peer.address.clone())
                .collect(),
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
        for peer in sources.peers {
            selected.insert(peer.node_id);
            client.add_peer_address(peer.node_id, peer.address).await?;
        }
        if let Some(guild) = discovery_guild {
            let discovered = tokio::time::timeout(
                Duration::from_secs(60),
                discover_peers(&client, &keys, guild),
            )
            .await
            .context("legacy recovery directory discovery timed out")??;
            for peer in discovered {
                selected.insert(peer.node_id);
                ensure!(
                    selected.len() <= 64,
                    "discovered survivor identities exceed the recovery bound"
                );
                client.add_peer_address(peer.node_id, peer.address).await?;
            }
        }
        let remote = PeerRecovery {
            client: recovery_client,
            runtime: tokio::runtime::Handle::current(),
            peers: selected,
        };
        tokio::task::spawn_blocking(move || operation(keys, data_dir, remote))
            .await
            .context("legacy peer read worker failed")?
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

async fn discover_peers(
    client: &P2pClient,
    keys: &KeyMaterial,
    guild: [u8; 32],
) -> Result<Vec<LegacyExportPeer>> {
    use futures::{StreamExt, stream};
    loop {
        let providers = match client
            .get_providers(crate::network::recovery_mailbox_key(keys.node_id()))
            .await
        {
            Ok(providers) => providers,
            Err(error) => {
                tracing::debug!(%error, "legacy recovery directory lookup is not ready");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        ensure!(
            providers.len() <= 64,
            "recovery directory provider bound exceeded"
        );
        let mut queries = stream::iter(providers.into_iter().map(|provider| async move {
            let key = crate::network::recovery_bundle_key(keys.node_id(), &provider);
            (provider, client.get_record(key).await)
        }))
        .buffer_unordered(4);
        let mut peers = Vec::new();
        while let Some((provider, records)) = queries.next().await {
            let locator = match records.and_then(|records| {
                crate::network::preserved_recovery_locator(keys, &provider, guild, records)
            }) {
                Ok(Some(locator)) => locator,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(%provider, %error, "ignored invalid legacy recovery directory candidate");
                    continue;
                }
            };
            if locator.publisher == keys.node_id() {
                continue;
            }
            for endpoint in locator.endpoints {
                peers.push(LegacyExportPeer {
                    node_id: locator.publisher,
                    address: crate::network::validate_published_endpoint(
                        locator.publisher,
                        &endpoint,
                    )?,
                });
            }
        }
        if !peers.is_empty() {
            return Ok(peers);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
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
        let scope = PreservedInputScope::default();
        assert!(scratch_parent(temp.path(), &paths[0], &paths[1..2], &paths[2..], &scope).is_ok());
        for path in &paths {
            assert!(scratch_parent(path, &paths[0], &paths[1..2], &paths[2..], &scope).is_err());
            assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
        }
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&paths[0], &alias).unwrap();
        assert!(scratch_parent(&alias, &paths[0], &paths[1..2], &paths[2..], &scope).is_err());
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

    #[test]
    fn legacy_peer_scratch_rejects_unverifiable_possible_root_identity() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("catalog");
        std::fs::create_dir(&data).unwrap();
        let mut scope = PreservedInputScope::default();
        // Ordinary temporary filesystems need no enrollment capability when
        // their ancestry cannot match a preserved native root.
        assert!(
            scratch_parent_with_native_lookup(temp.path(), &data, &[], &[], &scope, |_| panic!(
                "unnecessary stable identity lookup"
            ))
            .is_ok()
        );
        scope.native_roots.insert(mb_store::NativeFileId {
            filesystem_id: 7,
            inode: temp.path().metadata().unwrap().ino(),
        });
        let error = scratch_parent_with_native_lookup(temp.path(), &data, &[], &[], &scope, |_| {
            Err(mb_store::AnchorError::ReflinkUnavailable(
                std::io::Error::new(std::io::ErrorKind::Unsupported, "stable UUID unavailable"),
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("select another TMPDIR"));
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    }

    #[test]
    fn legacy_peer_preflight_preserves_closed_catalog_and_registered_inputs() {
        use crate::control::{GitRepositoryInfo, ProtectedRoot};
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        for wrapped in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("catalog");
            std::fs::create_dir(&data).unwrap();
            let root = temp.path().join("source");
            let history = temp
                .path()
                .join(OsString::from_vec(b"history-\xff".to_vec()));
            for path in [&root, &history] {
                std::fs::create_dir_all(path.join("nested")).unwrap();
                std::fs::write(path.join("preserve"), b"original bytes").unwrap();
            }
            let alias = temp.path().join("history-alias");
            std::os::unix::fs::symlink(&history, &alias).unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
            let store = if wrapped {
                crate::volume::open_control_store(&data, &keys).unwrap().0
            } else {
                ControlStore::open(data.join("control.db"), &keys).unwrap()
            };
            let id = uuid::Uuid::from_bytes([74; 16]);
            for path in [&root, &temp.path().join("missing-source")] {
                let registration = ProtectedRoot {
                    format_version: 4,
                    root_id: uuid::Uuid::new_v4(),
                    path: path.clone(),
                    filesystem_id: 7,
                    root_inode: 11,
                };
                store
                    .put_record(
                        "protected-root",
                        registration.root_id.as_bytes(),
                        &mb_core::canonical_bytes(&registration).unwrap(),
                    )
                    .unwrap();
            }
            store
                .put_record(
                    "git-repository",
                    id.as_bytes(),
                    &mb_core::canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id: id,
                        path: history.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            drop(store);
            let files = || -> std::collections::BTreeMap<_, _> {
                std::fs::read_dir(&data)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), std::fs::read(entry.path()).unwrap())
                    })
                    .collect()
            };
            let before = files();
            assert!(peer_client_preflight(&keys, &data, temp.path(), &[], false).is_ok());
            for path in [&root, &root.join("nested"), &history, &alias.join("nested")] {
                let error = peer_client_preflight(&keys, &data, path, &[], false).unwrap_err();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
            }
            let after = files();
            assert_eq!(
                before.keys().collect::<Vec<_>>(),
                after.keys().collect::<Vec<_>>()
            );
            for (name, bytes) in before {
                assert!(after[&name] == bytes, "changed preserved file: {name:?}");
            }
            for path in [&root, &history] {
                assert_eq!(
                    std::fs::read(path.join("preserve")).unwrap(),
                    b"original bytes"
                );
                assert_eq!(std::fs::read_dir(path).unwrap().count(), 2);
                assert_eq!(std::fs::read_dir(path.join("nested")).unwrap().count(), 0);
            }
        }
    }

    #[test]
    #[ignore = "requires a provisioned reflink filesystem"]
    fn legacy_peer_preflight_rejects_renamed_roots_by_stable_identity() {
        use crate::control::ProtectedRoot;
        let parent = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap();
        let temp = tempfile::tempdir_in(parent).unwrap();
        let data = temp.path().join("catalog");
        std::fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        let mut moved = Vec::new();
        for owner in ["registration", "binding", "stopped-capture"] {
            let old = temp.path().join(format!("source-{owner}"));
            std::fs::create_dir_all(old.join("nested")).unwrap();
            let native = mb_store::directory_identity(&old).unwrap();
            let id = uuid::Uuid::new_v4();
            if owner == "binding" {
                let binding = mb_store::SourceBackendBinding::guarded_link_freeze_v1(
                    id,
                    native.filesystem_id,
                    native.inode,
                    mb_store::filesystem_identity(&old).unwrap().mount_id,
                );
                store
                    .put_record(
                        "source-backend",
                        id.as_bytes(),
                        &mb_core::canonical_bytes(&binding).unwrap(),
                    )
                    .unwrap();
            } else if owner == "registration" {
                let registration = ProtectedRoot {
                    format_version: 4,
                    root_id: id,
                    path: old.clone(),
                    filesystem_id: native.filesystem_id,
                    root_inode: native.inode,
                };
                store
                    .put_record(
                        "protected-root",
                        id.as_bytes(),
                        &mb_core::canonical_bytes(&registration).unwrap(),
                    )
                    .unwrap();
            } else {
                let capture = mb_store::GuardedStoppedCaptureV1 {
                    format_version: 1,
                    metadata: mb_store::GuardedViewMetadataV1 {
                        format_version: 1,
                        anchor_id: uuid::Uuid::new_v4(),
                        lower_root_id: native,
                        root_mode: 0o700,
                        root_uid: 0,
                        root_gid: 0,
                        root_atime_secs: 0,
                        root_atime_nanos: 0,
                        root_modified_secs: 0,
                        root_modified_nanos: 0,
                        entries: vec![],
                    },
                    files: vec![],
                };
                store
                    .put_record(
                        "guarded-view-stopped-capture-v1",
                        id.as_bytes(),
                        &mb_core::canonical_bytes(&capture).unwrap(),
                    )
                    .unwrap();
            }
            let new = temp.path().join(format!("moved-{owner}"));
            std::fs::rename(&old, &new).unwrap();
            moved.push(new);
        }
        drop(store);
        assert!(peer_client_preflight(&keys, &data, temp.path(), &[], false).is_ok());
        for root in moved {
            // Inode equality across distinct stable filesystem identities is
            // not ownership; Btrfs subvolumes can reuse inode numbers.
            let native = mb_store::directory_identity(&root).unwrap();
            let mut unrelated = PreservedInputScope::default();
            unrelated.native_roots.insert(mb_store::NativeFileId {
                filesystem_id: native.filesystem_id.wrapping_add(1).max(1),
                inode: native.inode,
            });
            assert!(scratch_parent(&root, &data, &[], &[], &unrelated).is_ok());
            for path in [&root, &root.join("nested")] {
                let error = peer_client_preflight(&keys, &data, path, &[], false).unwrap_err();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
            }
            assert_eq!(std::fs::read_dir(root.join("nested")).unwrap().count(), 0);
        }
    }
}
