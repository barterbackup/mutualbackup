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
use super::local_inventory::PreservedInput;
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

#[derive(Clone, Copy, Debug)]
enum PlacementPurpose {
    PeerClient,
    Export,
}

impl PlacementPurpose {
    fn parent(self) -> &'static str {
        match self {
            Self::PeerClient => "temporary client parent must be a directory",
            Self::Export => "export destination parent must be a directory",
        }
    }

    fn outside(self) -> &'static str {
        match self {
            Self::PeerClient => {
                "temporary client directory must be outside preserved inputs; select another TMPDIR"
            }
            Self::Export => {
                "export destination must be outside preserved inputs; select another destination"
            }
        }
    }

    fn unverified(self) -> &'static str {
        match self {
            Self::PeerClient => {
                "cannot verify temporary client directory ancestry; select another TMPDIR"
            }
            Self::Export => "cannot verify export destination ancestry; select another destination",
        }
    }

    fn changed(self) -> &'static str {
        match self {
            Self::PeerClient => {
                "temporary client directory ancestry changed during preflight; select another TMPDIR"
            }
            Self::Export => {
                "export destination ancestry changed during preflight; select another destination"
            }
        }
    }
}

#[derive(Debug)]
struct PreservedAncestor {
    device: u64,
    inode: u64,
    native_id: Option<mb_store::NativeFileId>,
}

/// Placement state depends on the proposed parent's ancestry, not the number
/// of preserved owners. Only one repeated path hint is cached between rows.
#[derive(Debug)]
struct PreservedParentCheck {
    purpose: PlacementPurpose,
    parent: PathBuf,
    ancestors: Vec<PreservedAncestor>,
    ancestor_inodes: BTreeSet<u64>,
    last_hint: Option<PathBuf>,
}

impl PreservedParentCheck {
    fn new(candidate: &Path, data_dir: &Path, selected_inputs: &[PathBuf]) -> Result<Self> {
        Self::for_purpose(
            candidate,
            data_dir,
            selected_inputs,
            PlacementPurpose::PeerClient,
        )
    }

    fn for_purpose(
        candidate: &Path,
        data_dir: &Path,
        selected_inputs: &[PathBuf],
        purpose: PlacementPurpose,
    ) -> Result<Self> {
        let parent = candidate.canonicalize()?;
        ensure!(parent.is_dir(), purpose.parent());
        let mut ancestors = Vec::new();
        let mut ancestor_inodes = BTreeSet::new();
        for path in parent.ancestors() {
            let metadata = path.metadata()?;
            ancestor_inodes.insert(metadata.ino());
            ancestors.push(PreservedAncestor {
                device: metadata.dev(),
                inode: metadata.ino(),
                native_id: None,
            });
        }
        let checked = Self {
            purpose,
            parent,
            ancestors,
            ancestor_inodes,
            last_hint: None,
        };
        for path in std::iter::once(data_dir).chain(selected_inputs.iter().map(PathBuf::as_path)) {
            checked.reject_canonical_path(&path.canonicalize()?)?;
        }
        Ok(checked)
    }

    fn reject_canonical_path(&self, input: &Path) -> Result<()> {
        ensure!(!self.parent.starts_with(input), self.purpose.outside());
        let metadata = input.metadata()?;
        ensure!(
            !metadata.is_dir()
                || !self
                    .ancestors
                    .iter()
                    .any(|ancestor| ancestor.device == metadata.dev()
                        && ancestor.inode == metadata.ino()),
            self.purpose.outside()
        );
        Ok(())
    }

    fn check_hint(&mut self, input: &Path) -> Result<()> {
        if self.last_hint.as_deref() == Some(input) {
            return Ok(());
        }
        match input.canonicalize() {
            Ok(path) => self.reject_canonical_path(&path)?,
            // Recovery need not have original sources or anchor locations.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error).context("cannot inspect preserved input location"),
        }
        self.last_hint = Some(input.to_path_buf());
        Ok(())
    }

    fn check_recorded_native(&mut self, recorded: mb_store::NativeFileId) -> Result<()> {
        ensure!(
            !self
                .ancestors
                .iter()
                .any(|ancestor| ancestor.inode == recorded.inode
                    && ancestor.device == recorded.filesystem_id),
            self.purpose.outside()
        );
        self.check_native(recorded)
    }

    fn check_native(&mut self, root: mb_store::NativeFileId) -> Result<()> {
        self.check_native_with(root, |path| mb_store::directory_identity(path))
    }

    fn check_native_with(
        &mut self,
        root: mb_store::NativeFileId,
        native_identity: impl Fn(
            &Path,
        )
            -> std::result::Result<mb_store::NativeFileId, mb_store::AnchorError>,
    ) -> Result<()> {
        if !self.ancestor_inodes.contains(&root.inode) {
            return Ok(());
        }
        for (path, ancestor) in self.parent.ancestors().zip(&mut self.ancestors) {
            if ancestor.inode != root.inode {
                continue;
            }
            // An unverifiable possible match cannot rule out a renamed root,
            // including after a kernel/filesystem capability change. Successful
            // lookups are reused for all later owners with this ancestor inode.
            let identity = match ancestor.native_id {
                Some(identity) => identity,
                None => {
                    let identity = native_identity(path).context(self.purpose.unverified())?;
                    ancestor.native_id = Some(identity);
                    identity
                }
            };
            ensure!(root != identity, self.purpose.outside());
        }
        Ok(())
    }

    fn check_records(&mut self, control: &ControlStore, keys: &KeyMaterial) -> Result<()> {
        super::local_inventory::for_each_record(control, |record| {
            record.for_each_input(|input| match input {
                PreservedInput::PathHint(path) => self.check_hint(path),
                PreservedInput::NativeRoot(root) => self.check_native(root),
                PreservedInput::RecordedNativeRoot(root) => self.check_recorded_native(root),
            })
        })?;
        super::local_inventory::for_each_external_git_record(control, keys, |record| {
            use super::local_inventory::PreservedExternalGitRecord;
            match record {
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::LinkedWorktree(
                    info,
                )) => {
                    self.check_hint(&info.path)?;
                    self.check_recorded_native(info.root_id)?;
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::ObjectAnchor {
                    anchor,
                    ..
                }) => {
                    self.check_hint(&anchor.source_root_hint)?;
                    self.check_hint(&anchor.area.path_hint)?;
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::FetchIntent(
                    intent,
                )) => {
                    self.check_hint(&intent.source_root)?;
                    self.check_hint(&intent.source_path)?;
                }
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::MergeBlobIntent(intent),
                ) => {
                    let ownership = intent.plan.preserved_ownership()?;
                    self.check_hint(ownership.source_root)?;
                    self.check_hint(&ownership.area.path_hint)?;
                    if let Some(identity) = ownership.stable_root_identity {
                        self.check_native(identity)?;
                    } else {
                        self.check_recorded_native(ownership.recorded_root_identity)?;
                    }
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::MergeSession(_)) => {
                }
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::BlobImportIntent { plan, .. },
                ) => {
                    let ownership = plan.preserved_ownership()?;
                    self.check_hint(ownership.source_root)?;
                    self.check_hint(&ownership.area.path_hint)?;
                    if let Some(identity) = ownership.stable_root_identity {
                        self.check_native(identity)?;
                    } else {
                        self.check_recorded_native(ownership.recorded_root_identity)?;
                    }
                }
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::VerifiedFetchBlob { .. },
                ) => {}
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::WorktreeRemovalIntent(intent),
                ) => {
                    self.check_recorded_native(intent.root_id)?;
                    self.check_recorded_native(intent.marker_directory_id)?;
                    for directory in intent.directories {
                        self.check_recorded_native(directory.recorded_identity)?;
                    }
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::RemovalIntent {
                    recorded_root_identity,
                    ..
                }) => self.check_recorded_native(recorded_root_identity)?,
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::PruneIntent {
                    anchors,
                    ..
                }) => {
                    for anchor in &anchors {
                        self.check_hint(&anchor.source_root_hint)?;
                        self.check_hint(&anchor.area.path_hint)?;
                    }
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::StageIntent {
                    plan,
                    ..
                }) => {
                    let ownership = plan.preserved_ownership()?;
                    self.check_hint(ownership.source_root)?;
                    self.check_hint(&ownership.area.path_hint)?;
                    if let Some(identity) = ownership.stable_root_identity {
                        self.check_native(identity)?;
                    } else {
                        self.check_recorded_native(ownership.recorded_root_identity)?;
                    }
                }
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::SymlinkStageIntent { intent, .. },
                ) => {
                    self.check_hint(&intent.source_root)?;
                    self.check_recorded_native(intent.recorded_root_identity)?;
                    self.check_recorded_native(intent.recorded_catalog_identity)?;
                    if let Some(root) = &intent.catalog_root {
                        self.check_hint(root)?;
                    }
                    if let Some(plan) = &intent.plan {
                        let ownership = plan.preserved_ownership()?;
                        self.check_hint(ownership.source_root)?;
                        self.check_hint(&ownership.area.path_hint)?;
                        if let Some(identity) = ownership.stable_root_identity {
                            self.check_native(identity)?;
                        } else {
                            self.check_recorded_native(ownership.recorded_root_identity)?;
                        }
                    }
                }
                PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::AnchorAreaLocation { path, .. },
                ) => {
                    if path.is_absolute() {
                        self.check_hint(&path)?;
                    }
                }
                PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::IndexEntry {
                    ..
                })
                | PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::Reference {
                    ..
                })
                | PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::MetadataObject { .. },
                )
                | PreservedExternalGitRecord::Record(
                    mb_git::PreservedGitRecord::SelectedBranch { .. },
                )
                | PreservedExternalGitRecord::CatalogStatus { .. } => {}
            }
            Ok(())
        })
    }

    fn pin(self) -> Result<mb_store::PinnedDirectory> {
        let parent = mb_store::PinnedDirectory::open(&self.parent)?;
        let metadata = parent.as_file().metadata()?;
        let original = &self.ancestors[0];
        ensure!(
            metadata.dev() == original.device && metadata.ino() == original.inode,
            self.purpose.changed()
        );
        self.finish()?;
        Ok(parent)
    }

    fn finish(self) -> Result<PathBuf> {
        for (path, ancestor) in self.parent.ancestors().zip(&self.ancestors) {
            let metadata = path.metadata()?;
            ensure!(
                metadata.dev() == ancestor.device && metadata.ino() == ancestor.inode,
                self.purpose.changed()
            );
        }
        Ok(self.parent)
    }
}

/// Check every known local owner before export reads can create journals or
/// output. Keep the checked directory capability through recovery/publication.
pub(super) fn export_parent_preflight(
    keys: &KeyMaterial,
    data_dir: &Path,
    candidate: &Path,
    protected_inputs: &[PathBuf],
) -> Result<mb_store::PinnedDirectory> {
    crate::volume::with_inspected_control_snapshot(data_dir, keys, |control| {
        let mut checked = PreservedParentCheck::for_purpose(
            candidate,
            data_dir,
            protected_inputs,
            PlacementPurpose::Export,
        )?;
        checked.check_records(control, keys)?;
        checked.pin()
    })
}

pub(super) fn export_file_parent_preflight(
    candidate: &Path,
    revision_directory: &Path,
    sector_directory: &Path,
) -> Result<mb_store::PinnedDirectory> {
    PreservedParentCheck::for_purpose(
        candidate,
        revision_directory,
        &[sector_directory.to_path_buf()],
        PlacementPurpose::Export,
    )?
    .pin()
}

pub(super) fn peer_client_preflight(
    keys: &KeyMaterial,
    data_dir: &Path,
    candidate: &Path,
    protected_inputs: &[PathBuf],
    discover: bool,
) -> Result<(PathBuf, Option<[u8; 32]>)> {
    crate::volume::with_inspected_control_snapshot(data_dir, keys, |control| {
        let mut checked = PreservedParentCheck::new(candidate, data_dir, protected_inputs)?;
        checked.check_records(control, keys)?;
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
        Ok((checked.finish()?, guild))
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
    fn legacy_volume_placement_excludes_unselected_registry_paths_without_mutation() {
        use std::collections::BTreeMap;
        use std::os::unix::ffi::OsStringExt;

        fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, Option<blake3::Hash>)> {
            let mut pending = vec![root.to_path_buf()];
            let mut files = BTreeMap::new();
            while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(directory).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() {
                        pending.push(entry.path());
                    } else {
                        let bytes = std::fs::read(entry.path()).unwrap();
                        // Only an existing live control SHM read mark can change.
                        let hash =
                            (entry.file_name() != "control.db-shm").then(|| blake3::hash(&bytes));
                        files.insert(entry.path(), (bytes.len() as u64, hash));
                    }
                }
            }
            files
        }

        for journal_state in 0..3 {
            let area = tempfile::tempdir().unwrap();
            let state = area.path().join("state");
            let volume = area
                .path()
                .join(std::ffi::OsString::from_vec(b"volume-\xff".to_vec()));
            std::fs::create_dir(&volume).unwrap();
            let seed = Seed::from_bytes([75; 32]);
            let keys = KeyMaterial::from_seed(&seed);
            let mut node = Node::open(&state, seed).unwrap();
            node.database_shell_statement(None, "PRAGMA wal_autocheckpoint=0", true)
                .unwrap();
            node.database_shell_statement(None, "PRAGMA wal_checkpoint(TRUNCATE)", true)
                .unwrap();
            // The registry is deliberately committed only to WAL in live/copy cases.
            node.configure_storage_volumes(std::slice::from_ref(&volume), 65536, 0)
                .unwrap();
            assert!(state.join("control.db-wal").metadata().unwrap().len() > 32);
            let state = if journal_state == 1 {
                let copy = area.path().join("preserved");
                std::fs::create_dir(&copy).unwrap();
                for entry in std::fs::read_dir(&state).unwrap() {
                    let entry = entry.unwrap();
                    assert!(entry.file_type().unwrap().is_file());
                    if entry.file_name() != "control.db-shm" {
                        std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
                    }
                }
                copy
            } else {
                state
            };
            let _writer = if journal_state == 2 {
                Some(node)
            } else {
                drop(node);
                None
            };
            let nested = volume.join("nested");
            std::fs::create_dir(&nested).unwrap();
            std::fs::write(volume.join("original"), b"retained volume payload").unwrap();
            let alias = area.path().join("alias");
            std::os::unix::fs::symlink(&volume, &alias).unwrap();
            let safe = area.path().join("safe");
            std::fs::create_dir(&safe).unwrap();
            let before = (snapshot(&state), snapshot(&volume));
            for parent in [&volume, &nested, &alias, &alias.join("nested")] {
                let error = peer_client_preflight(&keys, &state, parent, &[], false).unwrap_err();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
                let error = export_parent_preflight(&keys, &state, parent, &[])
                    .err()
                    .unwrap();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
            }
            assert_eq!(
                peer_client_preflight(&keys, &state, &safe, &[], false).unwrap(),
                (safe.clone(), None)
            );
            assert!(export_parent_preflight(&keys, &state, &safe, &[]).is_ok());
            assert_eq!((snapshot(&state), snapshot(&volume)), before);
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
        }
    }

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
        assert!(PreservedParentCheck::new(temp.path(), &paths[0], &paths[1..]).is_ok());
        for path in &paths {
            assert!(PreservedParentCheck::new(path, &paths[0], &paths[1..]).is_err());
            assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
        }
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&paths[0], &alias).unwrap();
        assert!(PreservedParentCheck::new(&alias, &paths[0], &paths[1..]).is_err());
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
        let mut checked = PreservedParentCheck::new(temp.path(), &data, &[]).unwrap();
        // Ordinary temporary filesystems need no enrollment capability when
        // their ancestry cannot match a preserved native root.
        assert!(
            checked
                .check_native_with(
                    mb_store::NativeFileId {
                        filesystem_id: 7,
                        inode: data.metadata().unwrap().ino(),
                    },
                    |_| panic!("unnecessary stable identity lookup")
                )
                .is_ok()
        );
        let possible_root = mb_store::NativeFileId {
            filesystem_id: 7,
            inode: temp.path().metadata().unwrap().ino(),
        };
        let error = checked
            .check_native_with(possible_root, |_| {
                Err(mb_store::AnchorError::ReflinkUnavailable(
                    std::io::Error::new(std::io::ErrorKind::Unsupported, "stable UUID unavailable"),
                ))
            })
            .unwrap_err();
        assert!(error.to_string().contains("select another TMPDIR"));
        let actual = possible_root;
        checked
            .check_native_with(
                mb_store::NativeFileId {
                    filesystem_id: 8,
                    inode: actual.inode,
                },
                |_| Ok(actual),
            )
            .unwrap();
        // A previously accepted owner on another filesystem must not hide a
        // later exact owner; cache the observed ancestor, not the input ID.
        let error = checked
            .check_native_with(actual, |_| panic!("cached ancestor lookup"))
            .unwrap_err();
        assert!(error.to_string().contains("outside preserved inputs"));
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    }

    #[test]
    fn legacy_peer_scratch_conservatively_excludes_recorded_device_identity() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("catalog");
        std::fs::create_dir(&data).unwrap();
        let metadata = temp.path().metadata().unwrap();
        let mut checked = PreservedParentCheck::new(temp.path(), &data, &[]).unwrap();
        // This is the pre-stable-ID wire meaning, still legal in native plan 1.
        let error = checked
            .check_recorded_native(mb_store::NativeFileId {
                filesystem_id: metadata.dev(),
                inode: metadata.ino(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("outside preserved inputs"));
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    }

    #[test]
    fn legacy_peer_scratch_rejects_parent_replacement_during_inspection() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("catalog");
        let parent = temp.path().join("scratch-parent");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let checked = PreservedParentCheck::new(&parent, &data, &[]).unwrap();
        let export_checked =
            PreservedParentCheck::for_purpose(&parent, &data, &[], PlacementPurpose::Export)
                .unwrap();
        let original = temp.path().join("original-parent");
        std::fs::rename(&parent, &original).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let error = checked.finish().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ancestry changed during preflight")
        );
        let error = export_checked.pin().err().unwrap();
        assert!(
            error
                .to_string()
                .contains("export destination ancestry changed during preflight")
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
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
            assert!(export_parent_preflight(&keys, &data, temp.path(), &[]).is_ok());
            for path in [&root, &root.join("nested"), &history, &alias.join("nested")] {
                let error = peer_client_preflight(&keys, &data, path, &[], false).unwrap_err();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
                let error = export_parent_preflight(&keys, &data, path, &[])
                    .err()
                    .unwrap();
                assert!(
                    error
                        .to_string()
                        .contains("export destination must be outside preserved inputs")
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
        use std::os::unix::ffi::OsStrExt;
        let parent = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").unwrap();
        let temp = tempfile::tempdir_in(parent).unwrap();
        let data = temp.path().join("catalog");
        std::fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        let mut moved = Vec::new();
        for owner in [
            "registration",
            "binding",
            "stopped-capture",
            "capture-intent",
        ] {
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
            } else if owner == "capture-intent" {
                let area = mb_store::StableAnchorAreaLocator {
                    area_id: uuid::Uuid::new_v4(),
                    path_hint: temp.path().join("absent-area"),
                    filesystem_id: native.filesystem_id,
                    volume_root_hint: temp.path().to_path_buf(),
                };
                let plan: mb_store::ReflinkCapturePlan = mb_core::decode_canonical(
                    &mb_core::canonical_bytes(&(
                        1_u16,
                        uuid::Uuid::new_v4(),
                        old.as_os_str().as_bytes().to_vec(),
                        area,
                        (
                            native.filesystem_id,
                            native.inode,
                            0_u64,
                            0_i64,
                            0_i64,
                            0_i64,
                            0_i64,
                        ),
                        libc::S_IFDIR | 0o700,
                        0_i64,
                        0_u32,
                    ))
                    .unwrap(),
                )
                .unwrap();
                store
                    .put_record(
                        "capture-intent",
                        id.as_bytes(),
                        &mb_core::canonical_bytes(&(
                            1_u16,
                            [74_u8; 32],
                            id,
                            1_u64,
                            None::<[u8; 32]>,
                            &old,
                            plan,
                        ))
                        .unwrap(),
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
        assert!(export_parent_preflight(&keys, &data, temp.path(), &[]).is_ok());
        for root in moved {
            // Inode equality across distinct stable filesystem identities is
            // not ownership; Btrfs subvolumes can reuse inode numbers.
            let native = mb_store::directory_identity(&root).unwrap();
            let mut unrelated = PreservedParentCheck::new(&root, &data, &[]).unwrap();
            assert!(
                unrelated
                    .check_native(mb_store::NativeFileId {
                        filesystem_id: native.filesystem_id.wrapping_add(1).max(1),
                        inode: native.inode,
                    })
                    .is_ok()
            );
            for path in [&root, &root.join("nested")] {
                let error = peer_client_preflight(&keys, &data, path, &[], false).unwrap_err();
                assert!(
                    error.to_string().contains("outside preserved inputs"),
                    "{error:#}"
                );
                let error = export_parent_preflight(&keys, &data, path, &[])
                    .err()
                    .unwrap();
                assert!(
                    error
                        .to_string()
                        .contains("export destination must be outside preserved inputs")
                );
            }
            assert_eq!(std::fs::read_dir(root.join("nested")).unwrap().count(), 0);
        }
    }
}
