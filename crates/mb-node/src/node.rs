use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mb_core::{
    EndpointRecord, GuildCheckpoint, GuildGenesis, GuildInvite, KeyMaterial, Member,
    MemberSignature, NodeId, QuorumCheckpoint, QuorumGuildGenesis, RECOVERY_LOCATOR_DOMAIN,
    RecoveryBundle, RecoveryLocator, STORAGE_ACKNOWLEDGEMENT_DOMAIN, SectorId, SectorRef, Seed,
    ShardRole, SignedRecord, StorageAcknowledgement, UserRevision, V1_CATALOG_PAGE_BYTES,
    V1_MAX_CATALOG_PAGES, canonical_bytes, decode_canonical, seal_recovery_record, sector_root,
    synthetic_filler_sector,
};
use mb_store::{
    ControlStore, DatabaseError, ParityObject, ParityStore, filesystem_identity, probe_reflink,
};
use rand::RngCore;
use uuid::Uuid;

use crate::control::{NodeStatus, ProtectedRoot};
use crate::snapshot::{
    build_revision_restore, install_inline_recipe, install_recovered_sector_recipe,
    install_recovery_marker, legacy_native_directory_id, make_restore_root_private,
    native_directory_id, prepare_revision, publish_restore, reanchor_recovered_revision,
    reconcile_pending_captures, remove_recovery_marker, render_sector,
    restore_revision_from_source, restore_signed_root_metadata, verify_recovery_marker,
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
enum RecoveryJobState {
    Building,
    Ready,
    Complete,
    Published,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RecoveryJob {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: PathBuf,
    staging: PathBuf,
    staged_native_id: Option<(u64, u64)>,
    marker_name: String,
    ownership_marker: [u8; 32],
    state: RecoveryJobState,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RecoveryAttempt {
    format_version: u16,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalRecoveryResume {
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub generation: u64,
    pub revision_id: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct CoordinatorCommitJournal {
    format_version: u16,
    intent_id: [u8; 16],
    plan_hash: [u8; 32],
    guild_id: [u8; 32],
    checkpoint_hash: Option<[u8; 32]>,
}

const GUILD_INVITE_DOMAIN: &[u8] = b"mutualbackup/guild-invite/v1";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuildPeer {
    pub member: Member,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GuildPhase {
    Draft,
    Joining,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuildSummary {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub coordinator: NodeId,
    pub phase: GuildPhase,
    pub peers: Vec<GuildPeer>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackupDescriptor {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub owner: NodeId,
    pub revision_id: Uuid,
    pub total_pages: u32,
    pub object_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BackupJobState {
    Pending,
    Running,
    Committed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackupJob {
    pub format_version: u16,
    pub descriptor: BackupDescriptor,
    pub state: BackupJobState,
    pub checkpoint_hash: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DhtPublicationSet {
    pub checkpoint_hash: [u8; 32],
    pub endpoint: SignedRecord<EndpointRecord>,
    pub recovery: Vec<SignedRecord<RecoveryBundle>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhtSequenceFloors {
    pub endpoint: u64,
    pub recovery: BTreeMap<NodeId, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DhtPublicationState {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    endpoints: Vec<String>,
    expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotInfo {
    pub revision_id: Uuid,
    pub sequence: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuildDraft {
    format_version: u16,
    guild_id: [u8; 32],
    coordinator: NodeId,
    peers: Vec<GuildPeer>,
    issued_invites: Vec<SignedRecord<GuildInvite>>,
    used_invites: Vec<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct PendingGuild {
    format_version: u16,
    invite: SignedRecord<GuildInvite>,
    local_peer: GuildPeer,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GenesisSignatureLock {
    format_version: u16,
    genesis_hash: [u8; 32],
    genesis: GuildGenesis,
    signature: MemberSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct InstalledGuild {
    format_version: u16,
    certificate: QuorumGuildGenesis,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuildEndpointCache {
    format_version: u16,
    guild_id: [u8; 32],
    endpoints: Vec<(NodeId, Vec<String>)>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RootDirtyState {
    format_version: u16,
    dirty: bool,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct SeedRecoveryReadiness {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    confirmed_until_unix_seconds: u64,
    publishers: Vec<NodeId>,
}

pub type RecoveredShards = BTreeMap<([u8; 32], u8), Vec<u8>>;

/// An exclusive, process-lifetime claim on one initialized data directory.
///
/// The daemon acquires this before accepting an unlock secret, then moves a
/// clone into `Node` after the secret has been verified.
#[derive(Clone)]
pub struct LockedDataDir {
    path: PathBuf,
    _lock: Arc<File>,
}

pub struct Node {
    data_dir: PathBuf,
    _data_dir_lock: LockedDataDir,
    keys: Arc<KeyMaterial>,
    control: ControlStore,
    parity: ParityStore,
    parity_budget_bytes: u64,
}

#[derive(Clone)]
pub(crate) struct NodeReaderConfig {
    keys: Arc<KeyMaterial>,
    control_path: PathBuf,
    parity_path: PathBuf,
    volume_id: [u8; 16],
}

pub(crate) struct NodeReader {
    keys: Arc<KeyMaterial>,
    control: ControlStore,
    parity: ParityStore,
}

impl NodeReaderConfig {
    pub(crate) fn open(&self) -> Result<NodeReader> {
        Ok(NodeReader {
            keys: self.keys.clone(),
            control: ControlStore::open(&self.control_path, &self.keys)?,
            parity: ParityStore::open(&self.parity_path, &self.volume_id, &self.keys)?,
        })
    }

    pub(crate) fn keys(&self) -> &KeyMaterial {
        &self.keys
    }
}

impl NodeReader {
    pub(crate) fn advertised_member(&self, fallback_failure_domain: &str) -> Result<Member> {
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            return decode_canonical(&bytes).map_err(Into::into);
        }
        Ok(Member {
            node_id: self.keys.node_id(),
            recovery_public_key: self.keys.recovery_public_key(),
            failure_domain: fallback_failure_domain.to_owned(),
        })
    }

    pub(crate) fn authorize_member(&self, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
        authorize_member(&self.control, guild_id, caller)
    }

    pub(crate) fn backup_job(&self, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
        backup_job(&self.control, guild_id, revision_id)
    }

    pub(crate) fn installed_guild_certificate(
        &self,
        guild_id: [u8; 32],
    ) -> Result<QuorumGuildGenesis> {
        let installed = decode_installed_guild(
            &self
                .control
                .get_record("guild-installed", b"primary")?
                .context("this node has no installed guild")?,
        )?;
        if installed.certificate.genesis.guild_id != guild_id {
            anyhow::bail!("requested guild differs from installed guild");
        }
        Ok(installed.certificate)
    }

    pub(crate) fn sector_for_guild(
        &self,
        guild_id: &[u8; 32],
        sector_id: &SectorId,
    ) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id, Some(guild_id))
    }

    pub(crate) fn parity_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>> {
        let object = self.parity.load_ready(group_id, shard_index)?;
        if object.guild_id != *guild_id {
            anyhow::bail!("parity object does not belong to the requested guild");
        }
        Ok(object.bytes)
    }

    pub(crate) fn checkpoint_page(
        &self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        checkpoint_page(&self.control, guild_id, checkpoint_hash, page_index)
    }

    pub(crate) fn prepared_revision_page(
        &self,
        guild_id: &[u8; 32],
        revision_id: Uuid,
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        let bytes = self
            .control
            .get_record("user-revision", revision_id.as_bytes())?
            .context("prepared revision is unavailable")?;
        let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        revision.verify(b"mutualbackup/user-revision/v1")?;
        if revision.value.guild_id != *guild_id || revision.value.revision_id != revision_id {
            anyhow::bail!("prepared revision does not belong to the authorized guild");
        }
        Ok(self.control.protocol_record_page(
            "user-revision",
            revision_id.as_bytes(),
            page_index,
        )?)
    }
}

impl Node {
    pub fn lock_data_dir(data_dir: impl AsRef<Path>) -> Result<LockedDataDir> {
        let data_dir = data_dir.as_ref();
        fs::create_dir_all(data_dir)?;
        let data_dir = data_dir
            .canonicalize()
            .with_context(|| format!("cannot resolve data directory {}", data_dir.display()))?;
        set_private_directory(&data_dir)?;
        let lock = Arc::new(open_data_dir_lock(&data_dir)?);
        Ok(LockedDataDir {
            path: data_dir,
            _lock: lock,
        })
    }

    pub fn open(data_dir: impl AsRef<Path>, seed: Seed) -> Result<Self> {
        let locked = Self::lock_data_dir(data_dir)?;
        Self::open_locked(locked, seed)
    }

    pub fn open_locked(locked: LockedDataDir, seed: Seed) -> Result<Self> {
        let data_dir = locked.path.clone();
        let keys = Arc::new(KeyMaterial::from_seed(&seed));
        let mut volume_id = [0_u8; 16];
        volume_id.copy_from_slice(&blake3::hash(&keys.node_id().0).as_bytes()[..16]);
        let mut control = ControlStore::open(data_dir.join("control.db"), &keys)?;
        control.clear_recomputable_operations()?;
        reconcile_pending_captures(&control)?;
        let parity = ParityStore::open(data_dir.join("parity.db"), &volume_id, &keys)?;
        Ok(Self {
            data_dir,
            _data_dir_lock: locked,
            keys,
            control,
            parity,
            parity_budget_bytes: u64::MAX,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn keys(&self) -> &KeyMaterial {
        &self.keys
    }

    pub fn status(&self) -> Result<NodeStatus> {
        Ok(NodeStatus {
            format_version: 1,
            node_id: self.keys.node_id(),
            data_dir: self.data_dir.clone(),
            protected_root: self.protected_root()?,
            checkpoint_count: self.control.checkpoint_head_certificates()?.len() as u64,
            seed_recovery_ready: self.seed_recovery_ready()?,
            root_dirty: self.root_dirty()?,
            network: None,
        })
    }

    pub fn protected_root(&self) -> Result<Option<ProtectedRoot>> {
        let root: Option<ProtectedRoot> = self
            .control
            .get_record("node-config", b"protected-root")?
            .map(|bytes| decode_canonical::<ProtectedRoot>(&bytes).map_err(anyhow::Error::from))
            .transpose()?;
        if let Some(root) = &root {
            if !matches!(root.format_version, 2 | 3)
                || root.filesystem_id == 0
                || root.root_inode == 0
            {
                anyhow::bail!("invalid protected-root record");
            }
        }
        Ok(root)
    }

    pub fn add_protected_root(&mut self, source_root: &Path) -> Result<ProtectedRoot> {
        let source_root = source_root
            .canonicalize()
            .with_context(|| format!("cannot resolve protected root {}", source_root.display()))?;
        if !source_root.is_dir() {
            anyhow::bail!("protected root must be a directory");
        }
        if source_root.starts_with(&self.data_dir) || self.data_dir.starts_with(&source_root) {
            anyhow::bail!("protected root and daemon data directory must not overlap");
        }
        let filesystem = filesystem_identity(&source_root)?;
        let root_metadata = fs::symlink_metadata(&source_root)?;
        #[cfg(unix)]
        let root_inode = {
            use std::os::unix::fs::MetadataExt;
            root_metadata.ino()
        };
        #[cfg(not(unix))]
        let root_inode = 0;

        let configured = self.protected_root()?;
        if let Some(configured) = &configured {
            if configured.path != source_root {
                anyhow::bail!("the prototype supports exactly one protected root");
            }
            if configured.format_version == 3
                && configured.filesystem_id == filesystem.stable_id
                && configured.root_inode == root_inode
            {
                return Ok(configured.clone());
            }
        }

        probe_reflink(&source_root).context("protected root failed the reflink COW probe")?;
        let root = ProtectedRoot {
            format_version: 3,
            root_id: configured
                .map(|configured| configured.root_id)
                .unwrap_or_else(Uuid::new_v4),
            path: source_root,
            filesystem_id: filesystem.stable_id,
            root_inode,
        };
        self.control
            .put_record("node-config", b"protected-root", &canonical_bytes(&root)?)?;
        self.mark_root_dirty("protected root has not been backed up")?;
        Ok(root)
    }

    pub fn mark_root_dirty(&mut self, reason: &str) -> Result<()> {
        let mut reason = reason.to_owned();
        reason.truncate(512);
        self.control.put_record(
            "node-state",
            b"root-dirty",
            &canonical_bytes(&RootDirtyState {
                format_version: 1,
                dirty: true,
                reason,
            })?,
        )?;
        Ok(())
    }

    pub fn root_dirty(&self) -> Result<bool> {
        let Some(bytes) = self.control.get_record("node-state", b"root-dirty")? else {
            return Ok(self.protected_root()?.is_some());
        };
        let state: RootDirtyState = decode_canonical(&bytes)?;
        if state.format_version != 1 {
            anyhow::bail!("unsupported root dirty-state version");
        }
        Ok(state.dirty)
    }

    pub(crate) fn reader_config(&self) -> NodeReaderConfig {
        let mut volume_id = [0_u8; 16];
        volume_id.copy_from_slice(&blake3::hash(&self.keys.node_id().0).as_bytes()[..16]);
        NodeReaderConfig {
            keys: self.keys.clone(),
            control_path: self.control.path().to_path_buf(),
            parity_path: self.parity.path().to_path_buf(),
            volume_id,
        }
    }

    pub fn member(&self, failure_domain: impl Into<String>) -> Member {
        Member {
            node_id: self.keys.node_id(),
            recovery_public_key: self.keys.recovery_public_key(),
            failure_domain: failure_domain.into(),
        }
    }

    pub fn advertised_member(&self, fallback_failure_domain: &str) -> Result<Member> {
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            return decode_canonical(&bytes).map_err(Into::into);
        }
        Ok(self.member(fallback_failure_domain))
    }

    pub fn configure_failure_domain(&mut self, failure_domain: &str) -> Result<()> {
        if failure_domain.is_empty() {
            anyhow::bail!("failure domain must not be empty");
        }
        let expected = self.member(failure_domain);
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            let configured: Member = decode_canonical(&bytes)?;
            if configured != expected {
                anyhow::bail!("configured failure domain conflicts with durable node identity");
            }
        }
        for bytes in self.control.checkpoint_head_certificates()? {
            let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
            checkpoint.verify()?;
            let committed = checkpoint
                .checkpoint
                .members
                .iter()
                .find(|member| member.node_id == self.keys.node_id())
                .context("committed checkpoint does not contain the local node")?;
            if committed != &expected {
                anyhow::bail!("configured failure domain conflicts with committed membership");
            }
        }
        self.control
            .put_record("node-config", b"member", &canonical_bytes(&expected)?)?;
        Ok(())
    }

    pub fn configure_parity_budget(&mut self, budget_bytes: u64) -> Result<()> {
        if budget_bytes == 0 {
            anyhow::bail!("parity storage budget must be greater than zero");
        }
        self.parity_budget_bytes = budget_bytes;
        Ok(())
    }

    pub fn create_guild(&mut self, endpoints: Vec<String>) -> Result<GuildSummary> {
        self.ensure_no_guild_state()?;
        let member = self.configured_member()?;
        validate_endpoint_set(member.node_id, &endpoints)?;
        let mut guild_id = [0_u8; 32];
        while guild_id == [0; 32] {
            rand::rngs::OsRng.fill_bytes(&mut guild_id);
        }
        let draft = GuildDraft {
            format_version: 1,
            guild_id,
            coordinator: member.node_id,
            peers: vec![GuildPeer { member, endpoints }],
            issued_invites: Vec::new(),
            used_invites: Vec::new(),
        };
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(summary_from_draft(&draft))
    }

    pub fn issue_guild_invite(
        &mut self,
        coordinator_endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<SignedRecord<GuildInvite>> {
        let mut draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if draft.coordinator != self.keys.node_id() || draft.peers.len() >= 5 {
            anyhow::bail!("only an incomplete guild coordinator can issue invitations");
        }
        validate_endpoint_set(self.keys.node_id(), &coordinator_endpoints)?;
        if expires_at_unix_seconds <= unix_seconds() {
            anyhow::bail!("guild invitation expiry must be in the future");
        }
        let mut nonce = [0_u8; 16];
        while nonce == [0; 16]
            || draft
                .issued_invites
                .iter()
                .any(|invite| invite.value.nonce == nonce)
        {
            rand::rngs::OsRng.fill_bytes(&mut nonce);
        }
        let invite = SignedRecord::sign(
            GUILD_INVITE_DOMAIN,
            GuildInvite {
                format_version: 1,
                guild_id: draft.guild_id,
                coordinator: self.configured_member()?,
                coordinator_endpoints,
                nonce,
                expires_at_unix_seconds,
            },
            &self.keys,
        )?;
        invite.value.validate()?;
        draft.issued_invites.push(invite.clone());
        draft
            .issued_invites
            .sort_by_key(|invite| invite.value.nonce);
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(invite)
    }

    pub fn begin_join_guild(
        &mut self,
        invite: SignedRecord<GuildInvite>,
        endpoints: Vec<String>,
    ) -> Result<GuildPeer> {
        invite.verify(GUILD_INVITE_DOMAIN)?;
        invite.value.validate()?;
        if invite.signer != invite.value.coordinator.node_id
            || invite.value.expires_at_unix_seconds <= unix_seconds()
        {
            anyhow::bail!("guild invitation is not authentic or has expired");
        }
        let local_peer = GuildPeer {
            member: self.configured_member()?,
            endpoints,
        };
        validate_endpoint_set(local_peer.member.node_id, &local_peer.endpoints)?;
        if local_peer.member.node_id == invite.value.coordinator.node_id {
            anyhow::bail!("guild coordinator cannot join its own invitation");
        }
        if let Some(installed) = self.installed_guild()? {
            if installed.certificate.genesis.guild_id == invite.value.guild_id {
                return self
                    .guild_peers(&installed)?
                    .into_iter()
                    .find(|peer| peer.member.node_id == self.keys.node_id())
                    .context("installed guild omits the local peer");
            }
            anyhow::bail!("this node already belongs to another guild");
        }
        if self.guild_draft()?.is_some() {
            anyhow::bail!("a guild coordinator cannot join another guild");
        }
        let pending = PendingGuild {
            format_version: 1,
            invite,
            local_peer: local_peer.clone(),
        };
        if let Some(bytes) = self.control.get_record("guild-pending", b"primary")? {
            let existing: PendingGuild = decode_canonical(&bytes)?;
            if existing != pending {
                anyhow::bail!("this node already has a different pending guild invitation");
            }
            return Ok(local_peer);
        }
        self.control
            .put_record("guild-pending", b"primary", &canonical_bytes(&pending)?)?;
        Ok(local_peer)
    }

    pub fn accept_guild_join(
        &mut self,
        caller: NodeId,
        invite: &SignedRecord<GuildInvite>,
        peer: GuildPeer,
    ) -> Result<()> {
        invite.verify(GUILD_INVITE_DOMAIN)?;
        invite.value.validate()?;
        validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
        let mut draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if caller != peer.member.node_id
            || invite.signer != self.keys.node_id()
            || invite.value.coordinator.node_id != self.keys.node_id()
            || invite.value.guild_id != draft.guild_id
            || invite.value.expires_at_unix_seconds <= unix_seconds()
            || !draft.issued_invites.iter().any(|issued| issued == invite)
        {
            anyhow::bail!("guild join is not authorized by an issued invitation");
        }
        if draft.used_invites.contains(&invite.value.nonce) {
            if draft.peers.iter().any(|existing| existing == &peer) {
                return Ok(());
            }
            anyhow::bail!("guild invitation has already been used");
        }
        if draft.peers.len() >= 5
            || draft
                .peers
                .iter()
                .any(|existing| existing.member.node_id == peer.member.node_id)
            || draft
                .peers
                .iter()
                .any(|existing| existing.member.failure_domain == peer.member.failure_domain)
        {
            anyhow::bail!("guild member or failure domain is duplicated, or guild is full");
        }
        draft.peers.push(peer);
        draft.peers.sort_by_key(|entry| entry.member.node_id);
        draft.used_invites.push(invite.value.nonce);
        draft.used_invites.sort();
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(())
    }

    pub fn proposed_guild_genesis(&self) -> Result<(GuildGenesis, Vec<GuildPeer>)> {
        let draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if draft.coordinator != self.keys.node_id() || draft.peers.len() != 5 {
            anyhow::bail!("guild finalization requires exactly five accepted members");
        }
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: draft.guild_id,
            coordinator: draft.coordinator,
            members: draft.peers.iter().map(|peer| peer.member.clone()).collect(),
        };
        genesis.validate()?;
        Ok((genesis, draft.peers))
    }

    pub fn sign_guild_genesis(&mut self, genesis: &GuildGenesis) -> Result<MemberSignature> {
        genesis.validate()?;
        let local_member = genesis
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("guild genesis omits the local node")?;
        if local_member != &self.configured_member()? {
            anyhow::bail!("guild genesis conflicts with the durable local member identity");
        }
        if genesis.coordinator == self.keys.node_id() {
            let (expected, _) = self.proposed_guild_genesis()?;
            if &expected != genesis {
                anyhow::bail!("guild genesis differs from the coordinator draft");
            }
        } else {
            let pending = self
                .pending_guild()?
                .context("no pending invitation authorizes this guild")?;
            if pending.invite.value.guild_id != genesis.guild_id
                || pending.invite.value.coordinator.node_id != genesis.coordinator
                || !genesis
                    .members
                    .iter()
                    .any(|member| member == &pending.invite.value.coordinator)
            {
                anyhow::bail!("guild genesis differs from the accepted invitation");
            }
        }
        let genesis_hash = genesis.hash()?;
        if let Some(bytes) = self
            .control
            .get_record("guild-genesis-signature-lock", b"primary")?
        {
            let lock: GenesisSignatureLock = decode_canonical(&bytes)?;
            if lock.format_version != 1
                || lock.genesis_hash != genesis_hash
                || lock.genesis != *genesis
            {
                anyhow::bail!("local seed has already signed a conflicting guild genesis");
            }
            return Ok(lock.signature);
        }
        let signature = genesis.member_signature(&self.keys)?;
        let lock = GenesisSignatureLock {
            format_version: 1,
            genesis_hash,
            genesis: genesis.clone(),
            signature: signature.clone(),
        };
        self.control.put_record(
            "guild-genesis-signature-lock",
            b"primary",
            &canonical_bytes(&lock)?,
        )?;
        Ok(signature)
    }

    pub fn install_guild_genesis(
        &mut self,
        certificate: QuorumGuildGenesis,
        mut peers: Vec<GuildPeer>,
    ) -> Result<()> {
        certificate.verify()?;
        peers.sort_by_key(|peer| peer.member.node_id);
        if peers.len() != 5
            || peers
                .iter()
                .map(|peer| &peer.member)
                .ne(certificate.genesis.members.iter())
        {
            anyhow::bail!("guild endpoint roster does not match certified membership");
        }
        for peer in &peers {
            validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
        }
        let lock: GenesisSignatureLock = decode_canonical(
            &self
                .control
                .get_record("guild-genesis-signature-lock", b"primary")?
                .context("local node did not sign this guild genesis")?,
        )?;
        if lock.genesis_hash != certificate.hash()?
            || !certificate
                .signatures
                .iter()
                .any(|signature| signature == &lock.signature)
        {
            anyhow::bail!("guild certificate does not contain the locked local signature");
        }
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        if let Some(existing) = self.installed_guild()? {
            if existing != installed {
                anyhow::bail!("this node already has a different installed guild");
            }
            let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
            self.control.put_record(
                "guild-endpoints",
                b"primary",
                &canonical_bytes(&endpoint_cache)?,
            )?;
            return Ok(());
        }
        let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
        self.control.put_records(&[
            (
                "guild-installed".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&installed)?,
            ),
            (
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            ),
        ])?;
        Ok(())
    }

    pub fn adopt_recovered_guild(
        &mut self,
        certificate: QuorumGuildGenesis,
        mut peers: Vec<GuildPeer>,
    ) -> Result<()> {
        certificate.verify()?;
        let local_member = certificate
            .genesis
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("recovered guild does not contain this seed identity")?
            .clone();
        if local_member.recovery_public_key != self.keys.recovery_public_key() {
            anyhow::bail!("recovered guild has the wrong recovery key for this seed");
        }
        let local_signature = certificate
            .signatures
            .iter()
            .find(|signature| signature.signer == self.keys.node_id())
            .cloned()
            .context("recovered guild certificate omits this seed's signature")?;
        peers.sort_by_key(|peer| peer.member.node_id);
        if peers.len() != 5
            || peers
                .iter()
                .map(|peer| &peer.member)
                .ne(certificate.genesis.members.iter())
        {
            anyhow::bail!("recovered endpoint roster does not match guild membership");
        }
        for peer in &peers {
            if !peer.endpoints.is_empty() {
                validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
            }
        }
        let lock = GenesisSignatureLock {
            format_version: 1,
            genesis_hash: certificate.hash()?,
            genesis: certificate.genesis.clone(),
            signature: local_signature,
        };
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        if let Some(existing) = self.installed_guild()?
            && existing != installed
        {
            anyhow::bail!("this node already has different guild state");
        }
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            let configured: Member = decode_canonical(&bytes)?;
            if configured != local_member {
                anyhow::bail!("configured member conflicts with recovered guild membership");
            }
        }
        let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
        self.control.put_records(&[
            (
                "node-config".to_owned(),
                b"member".to_vec(),
                canonical_bytes(&local_member)?,
            ),
            (
                "guild-genesis-signature-lock".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&lock)?,
            ),
            (
                "guild-installed".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&installed)?,
            ),
            (
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            ),
            (
                "dht-recovery-sequence-probe".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&true)?,
            ),
        ])?;
        Ok(())
    }

    pub fn guild_summary(&self) -> Result<Option<GuildSummary>> {
        if let Some(installed) = self.installed_guild()? {
            return Ok(Some(GuildSummary {
                format_version: 1,
                guild_id: installed.certificate.genesis.guild_id,
                coordinator: installed.certificate.genesis.coordinator,
                phase: GuildPhase::Active,
                peers: self.guild_peers(&installed)?,
            }));
        }
        if let Some(draft) = self.guild_draft()? {
            return Ok(Some(summary_from_draft(&draft)));
        }
        if let Some(pending) = self.pending_guild()? {
            return Ok(Some(GuildSummary {
                format_version: 1,
                guild_id: pending.invite.value.guild_id,
                coordinator: pending.invite.value.coordinator.node_id,
                phase: GuildPhase::Joining,
                peers: vec![
                    GuildPeer {
                        member: pending.invite.value.coordinator,
                        endpoints: pending.invite.value.coordinator_endpoints,
                    },
                    pending.local_peer,
                ],
            }));
        }
        Ok(None)
    }

    pub fn pending_guild_join(&self) -> Result<Option<(SignedRecord<GuildInvite>, GuildPeer)>> {
        Ok(self
            .pending_guild()?
            .map(|pending| (pending.invite, pending.local_peer)))
    }

    pub fn cancel_pending_guild_join(&mut self) -> Result<()> {
        if !self.control.delete_record("guild-pending", b"primary")? {
            anyhow::bail!("this node has no pending guild join to cancel");
        }
        Ok(())
    }

    pub fn installed_guild_certificate(&self) -> Result<Option<QuorumGuildGenesis>> {
        Ok(self.installed_guild()?.map(|guild| guild.certificate))
    }

    pub fn guild_coordinator(&self, guild_id: &[u8; 32]) -> Result<Option<NodeId>> {
        guild_coordinator(&self.control, guild_id)
    }

    pub fn prepare_protected_backup(&mut self) -> Result<BackupDescriptor> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let guild_id = installed.certificate.genesis.guild_id;
        let root = self
            .protected_root()?
            .context("this node has no protected root")?;
        let current_filesystem = filesystem_identity(&root.path)?;
        let root_metadata = fs::symlink_metadata(&root.path)?;
        #[cfg(unix)]
        let root_inode = {
            use std::os::unix::fs::MetadataExt;
            root_metadata.ino()
        };
        #[cfg(not(unix))]
        let root_inode = 0;
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || !root.matches_identity(current_filesystem, root_inode)
        {
            anyhow::bail!("protected root identity changed");
        }
        let local_head = self
            .control
            .get_record("user-revision-head", &guild_id)?
            .map(|bytes| decode_canonical::<SignedRecord<UserRevision>>(&bytes))
            .transpose()?;
        let committed_sequence = self
            .control
            .checkpoint_head(&guild_id)?
            .map(|(_, _, bytes)| decode_canonical::<QuorumCheckpoint>(&bytes))
            .transpose()?
            .and_then(|checkpoint| {
                checkpoint
                    .checkpoint
                    .revisions
                    .into_iter()
                    .filter(|revision| revision.value.owner == self.keys.node_id())
                    .map(|revision| revision.value.sequence)
                    .max()
            })
            .unwrap_or(0);
        let sequence = match &local_head {
            Some(revision)
                if revision.value.sequence.checked_sub(1) == Some(committed_sequence) =>
            {
                revision.value.sequence
            }
            Some(revision) if revision.value.sequence == committed_sequence => committed_sequence
                .checked_add(1)
                .context("revision sequence exhausted")?,
            None if committed_sequence == 0 => 1,
            _ => anyhow::bail!("local revision head is inconsistent with the guild checkpoint"),
        };
        let revision_id = local_head
            .filter(|revision| revision.value.sequence == sequence)
            .map(|revision| revision.value.revision_id)
            .unwrap_or_else(|| deterministic_revision_id(guild_id, self.keys.node_id(), sequence));
        let revision = self.prepare_revision(
            guild_id,
            &root.path,
            sequence,
            Some(*revision_id.as_bytes()),
        )?;
        let bytes = canonical_bytes(&revision)?;
        let total_pages = bytes.len().div_ceil(V1_CATALOG_PAGE_BYTES);
        if total_pages == 0 || total_pages > V1_MAX_CATALOG_PAGES as usize {
            anyhow::bail!("prepared revision exceeds the catalog paging limit");
        }
        Ok(BackupDescriptor {
            format_version: 1,
            guild_id,
            owner: self.keys.node_id(),
            revision_id,
            total_pages: total_pages as u32,
            object_hash: *blake3::hash(&bytes).as_bytes(),
        })
    }

    pub fn enqueue_backup(
        &mut self,
        caller: NodeId,
        descriptor: BackupDescriptor,
    ) -> Result<BackupJob> {
        validate_backup_descriptor(&descriptor)?;
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        if installed.certificate.genesis.coordinator != self.keys.node_id()
            || installed.certificate.genesis.guild_id != descriptor.guild_id
            || descriptor.owner != caller
            || !installed
                .certificate
                .genesis
                .members
                .iter()
                .any(|member| member.node_id == caller)
        {
            anyhow::bail!("backup submission is not authorized for this coordinator");
        }
        if let Some(bytes) = self
            .control
            .get_record("backup-job", descriptor.revision_id.as_bytes())?
        {
            let mut existing: BackupJob = decode_canonical(&bytes)?;
            if existing.descriptor != descriptor {
                anyhow::bail!("backup job identity conflicts with a prior submission");
            }
            if existing.state == BackupJobState::Failed {
                existing.state = BackupJobState::Pending;
                existing.error = None;
                self.put_backup_job(&existing)?;
            }
            return Ok(existing);
        }
        let job = BackupJob {
            format_version: 1,
            descriptor,
            state: BackupJobState::Pending,
            checkpoint_hash: None,
            error: None,
        };
        self.put_backup_job(&job)?;
        Ok(job)
    }

    pub fn backup_job(&self, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
        backup_job(&self.control, guild_id, revision_id)
    }

    pub fn claim_backup_job(&mut self) -> Result<Option<BackupJob>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        if installed.certificate.genesis.coordinator != self.keys.node_id() {
            return Ok(None);
        }
        for (_, bytes) in self.control.records("backup-job")? {
            let mut job: BackupJob = decode_canonical(&bytes)?;
            if matches!(job.state, BackupJobState::Pending | BackupJobState::Running) {
                job.state = BackupJobState::Running;
                job.error = None;
                self.put_backup_job(&job)?;
                return Ok(Some(job));
            }
        }
        Ok(None)
    }

    pub fn complete_backup_job(
        &mut self,
        descriptor: &BackupDescriptor,
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup completion conflicts with the durable job");
        }
        job.state = BackupJobState::Committed;
        job.checkpoint_hash = Some(checkpoint_hash);
        job.error = None;
        self.put_backup_job(&job)
    }

    pub fn fail_backup_job(&mut self, descriptor: &BackupDescriptor, error: &str) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup failure conflicts with the durable job");
        }
        let mut error = error.to_owned();
        error.truncate(4096);
        job.state = BackupJobState::Failed;
        job.error = Some(error);
        self.put_backup_job(&job)
    }

    pub fn retry_failed_backup_job(&mut self, descriptor: &BackupDescriptor) -> Result<BackupJob> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup retry conflicts with the durable job");
        }
        if job.state == BackupJobState::Failed {
            job.state = BackupJobState::Pending;
            job.error = None;
            self.put_backup_job(&job)?;
        }
        Ok(job)
    }

    pub fn current_checkpoint(&self, guild_id: [u8; 32]) -> Result<Option<QuorumCheckpoint>> {
        self.control
            .checkpoint_head(&guild_id)?
            .map(|(_, _, bytes)| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn prepared_revision_bytes(
        &self,
        guild_id: [u8; 32],
        revision_id: Uuid,
    ) -> Result<Vec<u8>> {
        let bytes = self
            .control
            .get_record("user-revision", revision_id.as_bytes())?
            .context("prepared revision is unavailable")?;
        let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        revision.verify(b"mutualbackup/user-revision/v1")?;
        if revision.value.guild_id != guild_id || revision.value.revision_id != revision_id {
            anyhow::bail!("prepared revision has the wrong guild or revision identity");
        }
        Ok(bytes)
    }

    pub fn defer_backup_job(&mut self, descriptor: &BackupDescriptor, error: &str) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup retry conflicts with the durable job");
        }
        let mut error = error.to_owned();
        error.truncate(4096);
        job.state = BackupJobState::Pending;
        job.error = Some(error);
        self.put_backup_job(&job)
    }

    fn put_backup_job(&self, job: &BackupJob) -> Result<()> {
        self.control.put_record(
            "backup-job",
            job.descriptor.revision_id.as_bytes(),
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    fn configured_member(&self) -> Result<Member> {
        decode_canonical(
            &self
                .control
                .get_record("node-config", b"member")?
                .context("node failure domain has not been configured")?,
        )
        .map_err(Into::into)
    }

    fn guild_draft(&self) -> Result<Option<GuildDraft>> {
        self.control
            .get_record("guild-draft", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn pending_guild(&self) -> Result<Option<PendingGuild>> {
        self.control
            .get_record("guild-pending", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn installed_guild(&self) -> Result<Option<InstalledGuild>> {
        self.control
            .get_record("guild-installed", b"primary")?
            .map(|bytes| decode_installed_guild(&bytes))
            .transpose()
    }

    fn guild_endpoint_cache(&self) -> Result<Option<GuildEndpointCache>> {
        self.control
            .get_record("guild-endpoints", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn merged_guild_endpoint_cache(
        &self,
        installed: &InstalledGuild,
        peers: Vec<GuildPeer>,
    ) -> Result<GuildEndpointCache> {
        let guild_id = installed.certificate.genesis.guild_id;
        let mut endpoints = match self.guild_endpoint_cache()? {
            Some(cache) => {
                if cache.format_version != 1 || cache.guild_id != guild_id {
                    anyhow::bail!("cached guild endpoints belong to different guild state");
                }
                cache.endpoints.into_iter().collect::<BTreeMap<_, _>>()
            }
            None => BTreeMap::new(),
        };
        for peer in peers {
            if !installed
                .certificate
                .genesis
                .members
                .iter()
                .any(|member| member.node_id == peer.member.node_id)
            {
                anyhow::bail!("endpoint cache contains a nonmember");
            }
            if !peer.endpoints.is_empty() {
                endpoints.insert(peer.member.node_id, peer.endpoints);
            } else {
                endpoints.entry(peer.member.node_id).or_default();
            }
        }
        Ok(GuildEndpointCache {
            format_version: 1,
            guild_id,
            endpoints: installed
                .certificate
                .genesis
                .members
                .iter()
                .map(|member| {
                    (
                        member.node_id,
                        endpoints.remove(&member.node_id).unwrap_or_default(),
                    )
                })
                .collect(),
        })
    }

    fn guild_peers(&self, installed: &InstalledGuild) -> Result<Vec<GuildPeer>> {
        if installed.format_version != 2 {
            anyhow::bail!("unsupported installed guild format version");
        }
        let cache = self
            .guild_endpoint_cache()?
            .context("installed guild has no endpoint cache")?;
        if cache.format_version != 1
            || cache.guild_id != installed.certificate.genesis.guild_id
            || cache.endpoints.len() != installed.certificate.genesis.members.len()
        {
            anyhow::bail!("installed guild endpoint cache is inconsistent");
        }
        let mut endpoints = cache.endpoints.into_iter().collect::<BTreeMap<_, _>>();
        if endpoints.len() != installed.certificate.genesis.members.len() {
            anyhow::bail!("installed guild endpoint cache contains duplicate members");
        }
        installed
            .certificate
            .genesis
            .members
            .iter()
            .map(|member| {
                let endpoints = endpoints
                    .remove(&member.node_id)
                    .context("installed guild endpoint cache omits a member")?;
                if !endpoints.is_empty() {
                    validate_endpoint_set(member.node_id, &endpoints)?;
                }
                Ok(GuildPeer {
                    member: member.clone(),
                    endpoints,
                })
            })
            .collect()
    }

    fn ensure_no_guild_state(&self) -> Result<()> {
        if self.guild_draft()?.is_some()
            || self.pending_guild()?.is_some()
            || self.installed_guild()?.is_some()
        {
            anyhow::bail!("this node already has guild state");
        }
        Ok(())
    }

    pub fn begin_coordinator_commit(
        &mut self,
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
    ) -> Result<[u8; 32]> {
        if let Some(bytes) = self
            .control
            .get_record("coordinator-commit-intent", &intent_id)?
        {
            let journal: CoordinatorCommitJournal = decode_canonical(&bytes)?;
            if journal.format_version != 2
                || journal.intent_id != intent_id
                || journal.plan_hash != plan_hash
            {
                anyhow::bail!("coordinator commit journal is inconsistent");
            }
            return Ok(journal.guild_id);
        }
        let mut guild_id = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut guild_id);
        let journal = CoordinatorCommitJournal {
            format_version: 2,
            intent_id,
            plan_hash,
            guild_id,
            checkpoint_hash: None,
        };
        self.control.put_record(
            "coordinator-commit-intent",
            &intent_id,
            &canonical_bytes(&journal)?,
        )?;
        Ok(guild_id)
    }

    pub fn complete_coordinator_commit(
        &mut self,
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("coordinator-commit-intent", &intent_id)?
            .context("coordinator commit journal is unavailable")?;
        let mut journal: CoordinatorCommitJournal = decode_canonical(&bytes)?;
        if journal.format_version != 2
            || journal.intent_id != intent_id
            || journal.plan_hash != plan_hash
            || journal.guild_id != guild_id
            || journal
                .checkpoint_hash
                .is_some_and(|stored| stored != checkpoint_hash)
        {
            anyhow::bail!("coordinator commit completion conflicts with durable state");
        }
        let checkpoint = self.checkpoint(&checkpoint_hash)?;
        if checkpoint.checkpoint.guild_id != guild_id {
            anyhow::bail!("coordinator commit checkpoint belongs to another guild");
        }
        journal.checkpoint_hash = Some(checkpoint_hash);
        self.control.put_record(
            "coordinator-commit-intent",
            &intent_id,
            &canonical_bytes(&journal)?,
        )?;
        Ok(())
    }

    pub fn prepare_revision(
        &mut self,
        guild_id: [u8; 32],
        source_root: &Path,
        sequence: u64,
        operation_id: Option<[u8; 16]>,
    ) -> Result<SignedRecord<UserRevision>> {
        prepare_revision(
            &mut self.control,
            &self.keys,
            guild_id,
            source_root,
            sequence,
            operation_id.map(Uuid::from_bytes),
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
        render_sector(&self.control, &self.keys, sector_id, None)
    }

    pub fn sector_for_guild(&self, guild_id: &[u8; 32], sector_id: &SectorId) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id, Some(guild_id))
    }

    #[cfg(test)]
    pub(crate) fn local_sector_is_inline(&self, sector_id: &SectorId) -> Result<bool> {
        crate::snapshot::local_recipe_is_inline(&self.control, sector_id)
    }

    #[cfg(test)]
    pub(crate) fn forget_local_sector(&self, sector_id: &SectorId) -> Result<()> {
        if !self.control.delete_record("local-sector", sector_id)? {
            anyhow::bail!("local sector recipe is unavailable");
        }
        Ok(())
    }

    pub fn publish_verified_parity(
        &mut self,
        group: &mb_core::CodingGroup,
        information: &[Vec<u8>; 3],
        object: &ParityObject,
    ) -> Result<SignedRecord<StorageAcknowledgement>> {
        self.publish_verified_parity_with_operation(
            &parity_operation_id(&group.id, object.shard_index),
            group,
            information,
            object,
        )
    }

    pub fn publish_verified_parity_with_operation(
        &mut self,
        operation_id: &[u8; 16],
        group: &mb_core::CodingGroup,
        information: &[Vec<u8>; 3],
        object: &ParityObject,
    ) -> Result<SignedRecord<StorageAcknowledgement>> {
        self.validate_parity_assignment(group, object)?;
        group.verify_parity_shard(information, object.shard_index as usize, &object.bytes)?;
        let acknowledgement = StorageAcknowledgement {
            format_version: 1,
            operation_id: *operation_id,
            guild_id: object.guild_id,
            group_id: object.group_id,
            shard_index: object.shard_index,
            row: u16::from(object.shard_index - 3),
            root: object.root,
            holder: self.keys.node_id(),
        };
        acknowledgement.validate()?;
        let acknowledgement =
            SignedRecord::sign(STORAGE_ACKNOWLEDGEMENT_DOMAIN, acknowledgement, &self.keys)?;
        self.parity.stage_and_publish_ack(
            object,
            &canonical_bytes(&acknowledgement)?,
            self.parity_budget_bytes,
        )?;
        self.control.put_record(
            "local-parity-proof",
            &parity_proof_id(&group.id, object.shard_index),
            &canonical_bytes(group)?,
        )?;
        Ok(acknowledgement)
    }

    fn publish_validated_parity(
        &mut self,
        group: &mb_core::CodingGroup,
        object: &ParityObject,
    ) -> Result<()> {
        self.parity.stage_and_publish(object)?;
        self.control.put_record(
            "local-parity-proof",
            &parity_proof_id(&group.id, object.shard_index),
            &canonical_bytes(group)?,
        )?;
        Ok(())
    }

    fn validate_parity_assignment(
        &self,
        group: &mb_core::CodingGroup,
        object: &ParityObject,
    ) -> Result<()> {
        let ShardRole::Parity(role) = group
            .roles
            .get(object.shard_index as usize)
            .context("parity shard index is out of range")?
        else {
            anyhow::bail!("parity object is assigned to an information role");
        };
        if group.calculate_id()? != group.id
            || group.guild_id != object.guild_id
            || group.format_version != object.format_version
            || group.id != object.group_id
            || role.holder != self.keys.node_id()
            || role.root != object.root
        {
            anyhow::bail!("parity object does not match its local coding-group assignment");
        }
        Ok(())
    }

    pub fn parity(&self, group_id: &[u8; 32], shard_index: u8) -> Result<Vec<u8>> {
        Ok(self.parity.load_ready(group_id, shard_index)?.bytes)
    }

    pub fn parity_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>> {
        let object = self.parity.load_ready(group_id, shard_index)?;
        if object.guild_id != *guild_id {
            anyhow::bail!("parity object does not belong to the requested guild");
        }
        Ok(object.bytes)
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
        self.clear_root_dirty_if_committed(checkpoint)?;
        Ok(hash)
    }

    pub fn sign_checkpoint(&mut self, checkpoint: &GuildCheckpoint) -> Result<MemberSignature> {
        checkpoint.validate()?;
        self.validate_local_member(checkpoint)?;
        let configured: Member = decode_canonical(
            &self
                .control
                .get_record("node-config", b"member")?
                .context("node failure domain has not been configured")?,
        )?;
        let committed = checkpoint
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("checkpoint does not contain the local node")?;
        if committed != &configured {
            anyhow::bail!("checkpoint local membership conflicts with node configuration");
        }
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

    #[allow(clippy::too_many_arguments)]
    pub fn stage_checkpoint_page(
        &mut self,
        object_kind: &str,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
        total_pages: u32,
        page_hash: &[u8; 32],
        bytes: &[u8],
    ) -> Result<()> {
        self.control.stage_checkpoint_page(
            object_kind,
            guild_id,
            checkpoint_hash,
            page_index,
            total_pages,
            page_hash,
            bytes,
        )?;
        Ok(())
    }

    pub fn sign_staged_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
    ) -> Result<MemberSignature> {
        let bytes = self
            .control
            .assembled_checkpoint_object("body", guild_id, checkpoint_hash)?;
        let checkpoint: GuildCheckpoint = decode_canonical(&bytes)?;
        if checkpoint.guild_id != *guild_id || checkpoint.hash()? != *checkpoint_hash {
            anyhow::bail!("staged checkpoint body has the wrong identity");
        }
        self.sign_checkpoint(&checkpoint)
    }

    pub fn finalize_staged_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        if let Ok(existing) = self.checkpoint(checkpoint_hash)
            && existing.checkpoint.guild_id == *guild_id
        {
            self.control.clear_checkpoint_pages(checkpoint_hash)?;
            return Ok(*checkpoint_hash);
        }
        let bytes =
            self.control
                .assembled_checkpoint_object("certificate", guild_id, checkpoint_hash)?;
        let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
        if checkpoint.checkpoint.guild_id != *guild_id || checkpoint.hash()? != *checkpoint_hash {
            anyhow::bail!("staged checkpoint certificate has the wrong identity");
        }
        let hash = self.store_checkpoint(&checkpoint)?;
        self.control.clear_checkpoint_pages(checkpoint_hash)?;
        Ok(hash)
    }

    pub fn checkpoint_page(
        &self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        checkpoint_page(&self.control, guild_id, checkpoint_hash, page_index)
    }

    fn validate_local_member(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        if let Some(installed) = self.installed_guild()?
            && (checkpoint.guild_id != installed.certificate.genesis.guild_id
                || checkpoint.genesis_hash != installed.certificate.hash()?
                || checkpoint.members != installed.certificate.genesis.members)
        {
            anyhow::bail!("checkpoint is not bound to the installed guild genesis");
        }
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
                        let bytes =
                            self.sector_for_guild(&checkpoint.guild_id, &information.sector.id)?;
                        if bytes.len() != group.shard_size as usize
                            || sector_root(&bytes) != information.sector.root
                        {
                            anyhow::bail!("local information shard is not durable");
                        }
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let object = self.parity.load_ready(&group.id, index as u8)?;
                        let proof = self
                            .control
                            .get_record(
                                "local-parity-proof",
                                &parity_proof_id(&group.id, index as u8),
                            )?
                            .context("local parity coding proof is unavailable")?;
                        if object.format_version != group.format_version
                            || object.guild_id != checkpoint.guild_id
                            || object.root != parity.root
                            || proof != canonical_bytes(group)?
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

    fn clear_root_dirty_if_committed(&mut self, checkpoint: &QuorumCheckpoint) -> Result<()> {
        let Some(bytes) = self
            .control
            .get_record("user-revision-head", &checkpoint.checkpoint.guild_id)?
        else {
            return Ok(());
        };
        let local_head: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        if checkpoint.checkpoint.revisions.contains(&local_head) {
            self.control.put_record(
                "node-state",
                b"root-dirty",
                &canonical_bytes(&RootDirtyState {
                    format_version: 1,
                    dirty: false,
                    reason: "latest local revision is committed".to_owned(),
                })?,
            )?;
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
        self.recovery_record_for_endpoints(
            subject,
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            vec![endpoint],
            expires_at_unix_seconds,
        )
    }

    pub fn recovery_record_for_endpoints(
        &self,
        subject: &Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<mb_core::SealedRecoveryRecord> {
        let locator = RecoveryLocator {
            format_version: 1,
            subject: subject.node_id,
            publisher: self.keys.node_id(),
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            endpoints,
            expires_at_unix_seconds,
        };
        let signed = SignedRecord::sign(RECOVERY_LOCATOR_DOMAIN, locator, &self.keys)?;
        Ok(seal_recovery_record(
            subject.recovery_public_key,
            &canonical_bytes(&signed)?,
        )?)
    }

    pub fn build_dht_publications(
        &mut self,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
        sequence_floors: DhtSequenceFloors,
    ) -> Result<Option<DhtPublicationSet>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let guild_id = installed.certificate.genesis.guild_id;
        let Some(checkpoint) = self.current_checkpoint(guild_id)? else {
            return Ok(None);
        };
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        let local_id = self.keys.node_id();
        validate_endpoint_set(local_id, &endpoints)?;
        if expires_at_unix_seconds <= unix_seconds() {
            anyhow::bail!("DHT publication expiry must be in the future");
        }
        if let Some(bytes) = self.control.get_record("dht-publication", b"primary")? {
            let state: DhtPublicationState = decode_canonical(&bytes)?;
            if state.format_version == 1
                && state.checkpoint_hash == checkpoint_hash
                && state.endpoints == endpoints
                && state.expires_at_unix_seconds.saturating_add(5 * 60) >= expires_at_unix_seconds
            {
                let endpoint = self
                    .control
                    .get_record("dht-endpoint", b"primary")?
                    .context("DHT publication state has no endpoint record")?;
                let endpoint: SignedRecord<EndpointRecord> = decode_canonical(&endpoint)?;
                let mut recovery = Vec::new();
                for subject in installed
                    .certificate
                    .genesis
                    .members
                    .iter()
                    .filter(|member| member.node_id != local_id)
                {
                    let bundle = self
                        .control
                        .get_record("dht-recovery-bundle", &subject.node_id.0)?
                        .context("DHT publication state has no recovery bundle")?;
                    recovery.push(decode_canonical(&bundle)?);
                }
                return Ok(Some(DhtPublicationSet {
                    checkpoint_hash,
                    endpoint,
                    recovery,
                }));
            }
        }
        let endpoint_slot = publication_slot(b"endpoint", local_id, local_id, guild_id);
        let endpoint = SignedRecord::sign(
            b"mutualbackup/endpoint-record/v1",
            EndpointRecord {
                format_version: 1,
                publisher: local_id,
                sequence: self.next_recovery_publication_sequence(
                    &endpoint_slot,
                    sequence_floors.endpoint.max(1),
                )?,
                expires_at_unix_seconds,
                endpoints: endpoints.clone(),
            },
            &self.keys,
        )?;
        self.control
            .put_record("dht-endpoint", b"primary", &canonical_bytes(&endpoint)?)?;
        let mut recovery = Vec::new();
        for subject in installed
            .certificate
            .genesis
            .members
            .iter()
            .filter(|member| member.node_id != local_id)
        {
            let slot = publication_slot(b"recovery", subject.node_id, local_id, guild_id);
            let sequence = self.next_recovery_publication_sequence(
                &slot,
                sequence_floors
                    .recovery
                    .get(&subject.node_id)
                    .copied()
                    .unwrap_or(1)
                    .max(1),
            )?;
            let sealed = self.recovery_record_for_endpoints(
                subject,
                guild_id,
                checkpoint_hash,
                checkpoint.checkpoint.generation,
                endpoints.clone(),
                expires_at_unix_seconds,
            )?;
            let bundle = SignedRecord::sign(
                b"mutualbackup/recovery-bundle/v1",
                RecoveryBundle {
                    format_version: 1,
                    subject: subject.node_id,
                    publisher: local_id,
                    sequence,
                    expires_at_unix_seconds,
                    sealed,
                },
                &self.keys,
            )?;
            self.control.put_record(
                "dht-recovery-bundle",
                &subject.node_id.0,
                &canonical_bytes(&bundle)?,
            )?;
            recovery.push(bundle);
        }
        self.control.put_record(
            "dht-publication",
            b"primary",
            &canonical_bytes(&DhtPublicationState {
                format_version: 1,
                checkpoint_hash,
                endpoints,
                expires_at_unix_seconds,
            })?,
        )?;
        self.control.put_record(
            "dht-recovery-sequence-probe",
            b"primary",
            &canonical_bytes(&false)?,
        )?;
        Ok(Some(DhtPublicationSet {
            checkpoint_hash,
            endpoint,
            recovery,
        }))
    }

    pub fn dht_recovery_sequence_probe_subjects(&self) -> Result<Vec<NodeId>> {
        let required = self
            .control
            .get_record("dht-recovery-sequence-probe", b"primary")?
            .map(|bytes| decode_canonical::<bool>(&bytes))
            .transpose()?
            .unwrap_or(false);
        if !required {
            return Ok(Vec::new());
        }
        Ok(self
            .installed_guild()?
            .into_iter()
            .flat_map(|guild| guild.certificate.genesis.members)
            .filter(|member| member.node_id != self.keys.node_id())
            .map(|member| member.node_id)
            .collect())
    }

    pub fn update_seed_recovery_readiness(
        &mut self,
        checkpoint_hash: [u8; 32],
        confirmations: Vec<(NodeId, u64)>,
    ) -> Result<()> {
        let checkpoint = self.checkpoint(&checkpoint_hash)?;
        if checkpoint.checkpoint.guild_id
            != self
                .installed_guild()?
                .context("this node has no active guild")?
                .certificate
                .genesis
                .guild_id
        {
            anyhow::bail!("recovery readiness checkpoint belongs to another guild");
        }
        let now = unix_seconds();
        let mut by_publisher = BTreeMap::new();
        for (publisher, expires_at) in confirmations {
            if expires_at > now {
                by_publisher
                    .entry(publisher)
                    .and_modify(|current: &mut u64| *current = (*current).max(expires_at))
                    .or_insert(expires_at);
            }
        }
        let mut expiries = by_publisher.values().copied().collect::<Vec<_>>();
        expiries.sort_unstable_by(|left, right| right.cmp(left));
        let confirmed_until_unix_seconds = expiries.get(2).copied().unwrap_or(0);
        self.control.put_record(
            "seed-recovery-ready",
            b"primary",
            &canonical_bytes(&SeedRecoveryReadiness {
                format_version: 1,
                checkpoint_hash,
                confirmed_until_unix_seconds,
                publishers: by_publisher.into_keys().collect(),
            })?,
        )?;
        Ok(())
    }

    pub fn seed_recovery_ready(&self) -> Result<bool> {
        let Some(bytes) = self.control.get_record("seed-recovery-ready", b"primary")? else {
            return Ok(false);
        };
        let ready: SeedRecoveryReadiness = decode_canonical(&bytes)?;
        if ready.format_version != 1
            || ready.publishers.len() < 3
            || ready.confirmed_until_unix_seconds <= unix_seconds()
        {
            return Ok(false);
        }
        let Some(installed) = self.installed_guild()? else {
            return Ok(false);
        };
        Ok(self
            .current_checkpoint(installed.certificate.genesis.guild_id)?
            .is_some_and(|checkpoint| checkpoint.hash().ok() == Some(ready.checkpoint_hash)))
    }

    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let checkpoint = self
            .current_checkpoint(installed.certificate.genesis.guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        Ok(checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
            .map(|revision| SnapshotInfo {
                revision_id: revision.value.revision_id,
                sequence: revision.value.sequence,
                checkpoint_generation: checkpoint.checkpoint.generation,
                checkpoint_hash,
            })
            .collect())
    }

    pub fn restore_snapshot(
        &self,
        revision_id: Option<Uuid>,
        target: &Path,
    ) -> Result<SnapshotInfo> {
        if target.exists() {
            anyhow::bail!("restore target must not already exist");
        }
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let guild_id = installed.certificate.genesis.guild_id;
        let checkpoint = self
            .current_checkpoint(guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let revision = match revision_id {
            Some(revision_id) => checkpoint.checkpoint.revisions.iter().find(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.revision_id == revision_id
            }),
            None => checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == self.keys.node_id())
                .max_by_key(|revision| revision.value.sequence),
        }
        .context("requested snapshot is unavailable for this node")?;
        restore_revision_from_source(&self.keys, guild_id, revision, target, |sector_id| {
            self.sector_for_guild(&guild_id, sector_id)
        })?;
        Ok(SnapshotInfo {
            revision_id: revision.value.revision_id,
            sequence: revision.value.sequence,
            checkpoint_generation: checkpoint.checkpoint.generation,
            checkpoint_hash: checkpoint.hash()?,
        })
    }

    pub(crate) fn snapshot_repair_plan(
        &self,
        revision_id: Option<Uuid>,
    ) -> Result<(QuorumCheckpoint, SignedRecord<UserRevision>, Vec<GuildPeer>)> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let checkpoint = self
            .current_checkpoint(installed.certificate.genesis.guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let revision = match revision_id {
            Some(revision_id) => checkpoint.checkpoint.revisions.iter().find(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.revision_id == revision_id
            }),
            None => checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == self.keys.node_id())
                .max_by_key(|revision| revision.value.sequence),
        }
        .cloned()
        .context("requested snapshot is unavailable for this node")?;
        Ok((checkpoint, revision, self.guild_peers(&installed)?))
    }

    pub(crate) fn install_repaired_information_sector(
        &mut self,
        guild_id: [u8; 32],
        reference: SectorRef,
        ciphertext: &[u8],
    ) -> Result<()> {
        install_recovered_sector_recipe(
            &mut self.control,
            &self.keys,
            guild_id,
            reference,
            ciphertext,
        )
    }

    pub fn next_recovery_publication_sequence(
        &mut self,
        slot: &[u8; 32],
        minimum: u64,
    ) -> Result<u64> {
        if minimum == 0 {
            anyhow::bail!("recovery publication sequence must be positive");
        }
        let current = self
            .control
            .get_record("recovery-publication-sequence", slot)?
            .map(|bytes| decode_canonical::<u64>(&bytes))
            .transpose()?
            .unwrap_or(0);
        let next = current
            .checked_add(1)
            .context("recovery publication sequence exhausted")?
            .max(minimum);
        self.control.put_record(
            "recovery-publication-sequence",
            slot,
            &canonical_bytes(&next)?,
        )?;
        Ok(next)
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

    pub fn authorize_member(&self, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
        authorize_member(&self.control, guild_id, caller)
    }

    pub fn install_recovered_checkpoint(
        &mut self,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint)?;
        if !checkpoint.has_signature(self.keys.node_id()) {
            anyhow::bail!("checkpoint is not authorized by the recovering seed");
        }
        let checkpoint_hash = checkpoint.hash()?;
        for group in &checkpoint.checkpoint.coding_groups {
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRole::Information(information)
                        if information.owner == self.keys.node_id() =>
                    {
                        let bytes = self.control.recovery_shard(
                            &checkpoint_hash,
                            &checkpoint.checkpoint.guild_id,
                            &group.id,
                            index as u8,
                            &information.sector.root,
                        )?;
                        install_recovered_sector_recipe(
                            &mut self.control,
                            &self.keys,
                            checkpoint.checkpoint.guild_id,
                            information.sector.clone(),
                            &bytes,
                        )?;
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let bytes = self.control.recovery_shard(
                            &checkpoint_hash,
                            &checkpoint.checkpoint.guild_id,
                            &group.id,
                            index as u8,
                            &parity.root,
                        )?;
                        let object = ParityObject {
                            format_version: group.format_version,
                            guild_id: checkpoint.checkpoint.guild_id,
                            group_id: group.id,
                            shard_index: index as u8,
                            root: parity.root,
                            bytes,
                        };
                        self.validate_parity_assignment(group, &object)?;
                        self.publish_validated_parity(group, &object)?;
                    }
                    _ => {}
                }
            }
        }
        self.validate_local_roles(&checkpoint.checkpoint)?;
        self.control.commit_checkpoint(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &checkpoint_hash,
            &canonical_bytes(&checkpoint.checkpoint)?,
            &canonical_bytes(checkpoint)?,
            false,
        )?;
        if let Some(revision) = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
            .max_by_key(|revision| revision.value.sequence)
        {
            self.control.put_record(
                "user-revision-head",
                &checkpoint.checkpoint.guild_id,
                &canonical_bytes(revision)?,
            )?;
        }
        self.control.clear_recovery_shards(&checkpoint_hash)?;
        Ok(checkpoint_hash)
    }

    pub(crate) fn resume_local_recovery(
        &mut self,
        target: &Path,
    ) -> Result<Option<LocalRecoveryResume>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let guild_id = installed.certificate.genesis.guild_id;
        let Some(checkpoint) = self.current_checkpoint(guild_id)? else {
            return Ok(None);
        };
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint)?;
        let checkpoint_hash = checkpoint.hash()?;
        let revision = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
            .max_by_key(|revision| revision.value.sequence)
            .cloned();
        let revision_id = revision.as_ref().map(|revision| revision.value.revision_id);
        if let Some(revision) = revision {
            self.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, target)?;
        }
        Ok(Some(LocalRecoveryResume {
            guild_id,
            checkpoint_hash,
            generation: checkpoint.checkpoint.generation,
            revision_id,
        }))
    }

    pub(crate) fn pin_recovery_attempt(&mut self, checkpoint: &QuorumCheckpoint) -> Result<()> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint)?;
        let checkpoint_hash = checkpoint.hash()?;
        for (record_id, bytes) in self.control.records("recovery-job")? {
            if record_id.as_slice() == checkpoint_hash {
                continue;
            }
            if record_id.len() != checkpoint_hash.len() {
                anyhow::bail!("durable recovery job has an invalid checkpoint key");
            }
            let job: RecoveryJob = decode_canonical(&bytes)?;
            self.remove_superseded_recovery_job(&job)?;
        }
        let attempt = RecoveryAttempt {
            format_version: 1,
            guild_id: checkpoint.checkpoint.guild_id,
            checkpoint_hash,
            generation: checkpoint.checkpoint.generation,
        };
        self.control
            .pin_recovery_attempt(&checkpoint_hash, &canonical_bytes(&attempt)?)?;
        Ok(())
    }

    fn remove_superseded_recovery_job(&mut self, job: &RecoveryJob) -> Result<()> {
        if !matches!(job.format_version, 2 | 3 | 4 | 5) {
            anyhow::bail!("unsupported durable recovery job version");
        }
        let parent = containing_directory(&job.target);
        if job.staging.parent() != Some(parent)
            || !job
                .staging
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".mutualbackup-restore-"))
        {
            anyhow::bail!("durable recovery job contains an unsafe staging path");
        }
        if job.target.exists() && job.state != RecoveryJobState::Complete {
            anyhow::bail!("superseded recovery still owns an unfinished published target");
        }
        if job.staging.exists() {
            verify_recovery_job_staging(job, parent)?;
            make_restore_root_private(&job.staging)?;
            fs::remove_dir_all(&job.staging)?;
            sync_directory(parent)?;
        }
        if job.format_version >= 5 {
            remove_recovery_marker(parent, &job.marker_name, &job.ownership_marker)?;
        }
        Ok(())
    }

    pub fn stage_recovered_shard(
        &mut self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group: &mb_core::CodingGroup,
        shard_index: u8,
        bytes: &[u8],
    ) -> Result<()> {
        let role = group
            .roles
            .get(shard_index as usize)
            .context("recovered shard index is out of range")?;
        let root = match role {
            ShardRole::Information(information) if information.owner == self.keys.node_id() => {
                information.sector.root
            }
            ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => parity.root,
            _ => anyhow::bail!("recovered shard is not assigned to the local node"),
        };
        if group.guild_id != *guild_id {
            anyhow::bail!("recovered shard has the wrong guild context");
        }
        self.control.stage_recovery_shard(
            checkpoint_hash,
            guild_id,
            &group.id,
            shard_index,
            &root,
            bytes,
        )?;
        Ok(())
    }

    pub fn recovered_shard_is_staged(
        &self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group: &mb_core::CodingGroup,
        shard_index: u8,
    ) -> Result<bool> {
        let role = group
            .roles
            .get(shard_index as usize)
            .context("recovered shard index is out of range")?;
        let root = match role {
            ShardRole::Information(information) if information.owner == self.keys.node_id() => {
                information.sector.root
            }
            ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => parity.root,
            _ => anyhow::bail!("recovered shard is not assigned to the local node"),
        };
        if group.guild_id != *guild_id {
            anyhow::bail!("recovered shard has the wrong guild context");
        }
        match self
            .control
            .recovery_shard(checkpoint_hash, guild_id, &group.id, shard_index, &root)
        {
            Ok(_) => Ok(true),
            Err(DatabaseError::NotReady) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn restore_recovered_revision(
        &mut self,
        checkpoint_hash: &[u8; 32],
        guild_id: [u8; 32],
        revision: &SignedRecord<UserRevision>,
        target: &Path,
    ) -> Result<()> {
        let parent = containing_directory(target);
        fs::create_dir_all(parent)?;
        let existing = self.control.get_record("recovery-job", checkpoint_hash)?;
        let mut job = match existing {
            Some(bytes) => {
                let mut job: RecoveryJob = decode_canonical(&bytes)?;
                if !matches!(job.format_version, 2 | 3 | 4 | 5)
                    || job.guild_id != guild_id
                    || job.revision_id != revision.value.revision_id
                    || job.target != target
                    || job.staging.parent() != Some(parent)
                {
                    anyhow::bail!("recovery job conflicts with durable local state");
                }
                if job.format_version == 2 {
                    if job.state == RecoveryJobState::Complete {
                        job.state = RecoveryJobState::Published;
                    }
                }
                if job.format_version < 4 {
                    let owned_path = if target.exists() {
                        Some(target)
                    } else if job.staging.exists() {
                        Some(job.staging.as_path())
                    } else {
                        None
                    };
                    if let (Some(expected), Some(owned_path)) = (job.staged_native_id, owned_path) {
                        if legacy_native_directory_id(owned_path)? != expected {
                            anyhow::bail!("legacy recovery object changed unexpectedly");
                        }
                        job.staged_native_id = Some(native_directory_id(owned_path)?);
                    } else if owned_path.is_none() {
                        job.staged_native_id = None;
                    }
                    job.format_version = 4;
                    self.control.put_record(
                        "recovery-job",
                        checkpoint_hash,
                        &canonical_bytes(&job)?,
                    )?;
                }
                job
            }
            None => {
                let marker_id = Uuid::new_v4();
                let mut ownership_marker = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut ownership_marker);
                RecoveryJob {
                    format_version: 5,
                    guild_id,
                    revision_id: revision.value.revision_id,
                    target: target.to_path_buf(),
                    staging: parent.join(format!(".mutualbackup-restore-{}", Uuid::new_v4())),
                    staged_native_id: None,
                    marker_name: format!(".mutualbackup-recovery-ownership-{marker_id}"),
                    ownership_marker,
                    state: RecoveryJobState::Building,
                }
            }
        };

        if target.exists() {
            let expected = job
                .staged_native_id
                .context("existing restore target is not owned by this recovery job")?;
            if native_directory_id(target)? != expected {
                anyhow::bail!("existing restore target was created by another actor");
            }
            match job.state {
                RecoveryJobState::Complete => {
                    reanchor_recovered_revision(
                        &mut self.control,
                        &self.keys,
                        guild_id,
                        revision,
                        target,
                    )?;
                    return Ok(());
                }
                RecoveryJobState::Ready => {
                    verify_recovery_job_marker(&job, target, parent)?;
                    sync_directory(parent)?;
                    job.state = RecoveryJobState::Published;
                    self.control.put_record(
                        "recovery-job",
                        checkpoint_hash,
                        &canonical_bytes(&job)?,
                    )?;
                }
                RecoveryJobState::Published => {}
                RecoveryJobState::Building => {
                    anyhow::bail!(
                        "existing restore target is not owned by a publishable recovery job"
                    );
                }
            }
            return self.finish_recovery(&mut job, checkpoint_hash, revision, target);
        }

        if job.state == RecoveryJobState::Ready && job.staging.exists() {
            let expected = job
                .staged_native_id
                .context("ready recovery job has no staged native identity")?;
            if native_directory_id(&job.staging)? != expected {
                anyhow::bail!("ready recovery staging directory changed unexpectedly");
            }
            verify_recovery_job_marker(&job, &job.staging, parent)?;
            publish_restore(&job.staging, target)?;
            job.state = RecoveryJobState::Published;
            self.control
                .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
            return self.finish_recovery(&mut job, checkpoint_hash, revision, target);
        }

        if matches!(
            job.state,
            RecoveryJobState::Published | RecoveryJobState::Complete
        ) {
            anyhow::bail!("published recovery target disappeared");
        }

        if job.staging.exists() {
            verify_recovery_job_staging(&job, parent)?;
            make_restore_root_private(&job.staging)?;
            fs::remove_dir_all(&job.staging)?;
            sync_directory(parent)?;
        }
        if job.format_version >= 5 {
            remove_recovery_marker(parent, &job.marker_name, &job.ownership_marker)?;
        }
        job.state = RecoveryJobState::Building;
        job.staged_native_id = None;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        if job.format_version >= 5 {
            install_recovery_marker(parent, &job.marker_name, &job.ownership_marker)?;
            fs::create_dir(&job.staging)?;
            make_restore_root_private(&job.staging)?;
            sync_directory(parent)?;
            job.staged_native_id = Some(native_directory_id(&job.staging)?);
            self.control
                .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        }
        build_revision_restore(
            &self.keys,
            guild_id,
            revision,
            &job.staging,
            &mut |sector_id| self.sector(sector_id),
            false,
        )?;
        restore_signed_root_metadata(&self.control, &self.keys, guild_id, revision, &job.staging)?;
        reanchor_recovered_revision(
            &mut self.control,
            &self.keys,
            guild_id,
            revision,
            &job.staging,
        )?;
        make_restore_root_private(&job.staging)?;
        if job.format_version < 5 {
            install_recovery_marker(&job.staging, &job.marker_name, &job.ownership_marker)?;
        }
        job.staged_native_id = Some(native_directory_id(&job.staging)?);
        job.state = RecoveryJobState::Ready;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        publish_restore(&job.staging, target)?;
        job.state = RecoveryJobState::Published;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        self.finish_recovery(&mut job, checkpoint_hash, revision, target)
    }

    fn finish_recovery(
        &mut self,
        job: &mut RecoveryJob,
        checkpoint_hash: &[u8; 32],
        revision: &SignedRecord<UserRevision>,
        target: &Path,
    ) -> Result<()> {
        make_restore_root_private(target)?;
        let marker_root = if job.format_version >= 5 {
            containing_directory(target)
        } else {
            target
        };
        remove_recovery_marker(marker_root, &job.marker_name, &job.ownership_marker)?;
        if !revision.value.metadata_sectors.is_empty() {
            restore_signed_root_metadata(
                &self.control,
                &self.keys,
                job.guild_id,
                revision,
                target,
            )?;
        }
        job.state = RecoveryJobState::Complete;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(job)?)?;
        Ok(())
    }

    pub fn cached_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: NodeId,
        request_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .control
            .begin_operation(operation_id, kind, &caller.0, request_hash)?)
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

fn decode_installed_guild(bytes: &[u8]) -> Result<InstalledGuild> {
    let installed: InstalledGuild = decode_canonical(bytes)?;
    if installed.format_version != 2 {
        anyhow::bail!("unsupported installed guild format version");
    }
    installed.certificate.verify()?;
    Ok(installed)
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn verify_recovery_job_marker(job: &RecoveryJob, owned_path: &Path, parent: &Path) -> Result<()> {
    let marker_root = if job.format_version >= 5 {
        parent
    } else {
        owned_path
    };
    verify_recovery_marker(marker_root, &job.marker_name, &job.ownership_marker)
}

fn verify_recovery_job_staging(job: &RecoveryJob, parent: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(&job.staging)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("recovery staging path is not a safe directory");
    }
    if let Some(expected) = job.staged_native_id {
        let actual = if job.format_version >= 4 {
            native_directory_id(&job.staging)?
        } else {
            legacy_native_directory_id(&job.staging)?
        };
        if actual != expected {
            anyhow::bail!("recovery staging directory changed unexpectedly");
        }
    } else if job.format_version >= 5 {
        // The external marker makes the short mkdir-to-ID-persist window
        // recognizable without trusting an attacker-replaceable path alone.
        verify_recovery_job_marker(job, &job.staging, parent)?;
    }
    if job.format_version >= 5 || job.state == RecoveryJobState::Ready {
        verify_recovery_job_marker(job, &job.staging, parent)?;
    }
    Ok(())
}

fn authorize_member(control: &ControlStore, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
    if let Some(bytes) = control.get_record("guild-installed", b"primary")? {
        let installed = decode_installed_guild(&bytes)?;
        if installed.certificate.genesis.guild_id != *guild_id
            || !installed
                .certificate
                .genesis
                .members
                .iter()
                .any(|member| member.node_id == caller)
        {
            anyhow::bail!("caller is not an authorized guild member");
        }
        return Ok(());
    }
    let (_, _, bytes) = control
        .checkpoint_head(guild_id)?
        .context("guild has no locally committed checkpoint")?;
    let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
    checkpoint.verify()?;
    if checkpoint.checkpoint.guild_id != *guild_id
        || !checkpoint
            .checkpoint
            .members
            .iter()
            .any(|member| member.node_id == caller)
    {
        anyhow::bail!("caller is not an authorized guild member");
    }
    Ok(())
}

fn guild_coordinator(control: &ControlStore, guild_id: &[u8; 32]) -> Result<Option<NodeId>> {
    let Some(bytes) = control.get_record("guild-installed", b"primary")? else {
        return Ok(None);
    };
    let installed = decode_installed_guild(&bytes)?;
    if installed.certificate.genesis.guild_id != *guild_id {
        anyhow::bail!("requested guild differs from installed guild");
    }
    Ok(Some(installed.certificate.genesis.coordinator))
}

fn backup_job(control: &ControlStore, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
    let job: BackupJob = decode_canonical(
        &control
            .get_record("backup-job", revision_id.as_bytes())?
            .context("backup job is unavailable")?,
    )?;
    if job.format_version != 1 || job.descriptor.guild_id != guild_id {
        anyhow::bail!("backup job belongs to another guild");
    }
    Ok(job)
}

fn summary_from_draft(draft: &GuildDraft) -> GuildSummary {
    GuildSummary {
        format_version: 1,
        guild_id: draft.guild_id,
        coordinator: draft.coordinator,
        phase: GuildPhase::Draft,
        peers: draft.peers.clone(),
    }
}

fn validate_endpoint_set(node_id: NodeId, endpoints: &[String]) -> Result<()> {
    use libp2p::multiaddr::Protocol;

    if endpoints.is_empty() || endpoints.len() > 8 {
        anyhow::bail!("a guild peer must advertise between one and eight endpoints");
    }
    let expected = node_id.libp2p_peer_id()?;
    let mut unique = std::collections::BTreeSet::new();
    for endpoint in endpoints {
        if endpoint.len() > 512 || !unique.insert(endpoint) {
            anyhow::bail!("guild endpoint is duplicated or too long");
        }
        let address: libp2p::Multiaddr = endpoint
            .parse()
            .with_context(|| format!("invalid guild endpoint {endpoint}"))?;
        if address.iter().last() != Some(Protocol::P2p(expected)) {
            anyhow::bail!("guild endpoint is not bound to its seed-derived peer identity");
        }
    }
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn deterministic_revision_id(guild_id: [u8; 32], owner: NodeId, sequence: u64) -> Uuid {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup revision operation v1");
    hasher.update(&guild_id);
    hasher.update(&owner.0);
    hasher.update(&sequence.to_le_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Uuid::from_bytes(bytes)
}

fn validate_backup_descriptor(descriptor: &BackupDescriptor) -> Result<()> {
    if descriptor.format_version != 1
        || descriptor.guild_id == [0; 32]
        || descriptor.total_pages == 0
        || descriptor.total_pages > V1_MAX_CATALOG_PAGES
        || descriptor.object_hash == [0; 32]
    {
        anyhow::bail!("invalid backup descriptor");
    }
    Ok(())
}

fn checkpoint_page(
    control: &ControlStore,
    guild_id: &[u8; 32],
    checkpoint_hash: &[u8; 32],
    page_index: u32,
) -> Result<(u32, Vec<u8>)> {
    let (_, head_hash, _) = control
        .checkpoint_head(guild_id)?
        .context("guild checkpoint is unavailable")?;
    if head_hash != *checkpoint_hash {
        anyhow::bail!("only the current checkpoint is page-readable");
    }
    Ok(control.protocol_record_page("guild-checkpoint", checkpoint_hash, page_index)?)
}

fn parity_proof_id(group_id: &[u8; 32], shard_index: u8) -> [u8; 33] {
    let mut id = [0_u8; 33];
    id[..32].copy_from_slice(group_id);
    id[32] = shard_index;
    id
}

fn parity_operation_id(group_id: &[u8; 32], shard_index: u8) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup parity operation v1");
    hasher.update(group_id);
    hasher.update(&[shard_index]);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn publication_slot(
    kind: &[u8],
    subject: NodeId,
    publisher: NodeId,
    guild_id: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup dht publication slot v1");
    hasher.update(kind);
    hasher.update(&subject.0);
    hasher.update(&publisher.0);
    hasher.update(&guild_id);
    *hasher.finalize().as_bytes()
}

fn open_data_dir_lock(data_dir: &Path) -> Result<File> {
    use fs2::FileExt;

    let path = data_dir.join(".node.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    FileExt::try_lock_exclusive(&file).context("node data directory is already in use")?;
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_guild_fixture() -> (Seed, QuorumGuildGenesis, Vec<GuildPeer>) {
        let mut identities = (0_u8..5)
            .map(|index| {
                let seed = Seed::from_bytes([index + 120; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                (keys.node_id(), seed, keys.recovery_public_key())
            })
            .collect::<Vec<_>>();
        identities.sort_by_key(|(node_id, _, _)| *node_id);
        let members = identities
            .iter()
            .enumerate()
            .map(|(index, (node_id, _, recovery_public_key))| Member {
                node_id: *node_id,
                recovery_public_key: *recovery_public_key,
                failure_domain: format!("recovery-domain-{index}"),
            })
            .collect::<Vec<_>>();
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: [121; 32],
            coordinator: members[0].node_id,
            members: members.clone(),
        };
        let signatures = identities
            .iter()
            .map(|(_, seed, _)| {
                genesis
                    .member_signature(&KeyMaterial::from_seed(seed))
                    .unwrap()
            })
            .collect();
        let certificate = QuorumGuildGenesis {
            genesis,
            signatures,
        };
        certificate.verify().unwrap();
        let peers = members
            .into_iter()
            .enumerate()
            .map(|(index, member)| GuildPeer {
                endpoints: vec![format!(
                    "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
                    41_000 + index,
                    member.node_id.libp2p_peer_id().unwrap()
                )],
                member,
            })
            .collect();
        (identities[2].1.clone(), certificate, peers)
    }

    #[test]
    fn data_directory_has_one_live_owner() {
        let temp = tempfile::tempdir().unwrap();
        let first = Node::open(temp.path(), Seed::from_bytes([91; 32])).unwrap();
        assert!(Node::open(temp.path(), Seed::from_bytes([91; 32])).is_err());
        drop(first);
        Node::open(temp.path(), Seed::from_bytes([91; 32])).unwrap();
    }

    #[test]
    fn coordinator_commit_retries_are_explicitly_bound_to_an_intent() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([90; 32])).unwrap();
        let first = node.begin_coordinator_commit([1; 16], [2; 32]).unwrap();
        assert_eq!(
            node.begin_coordinator_commit([1; 16], [2; 32]).unwrap(),
            first
        );
        assert!(node.begin_coordinator_commit([1; 16], [3; 32]).is_err());
        let second = node.begin_coordinator_commit([4; 16], [2; 32]).unwrap();
        assert_ne!(second, first);
    }

    #[test]
    fn failure_domain_is_a_durable_part_of_local_identity() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([89; 32])).unwrap();
        node.configure_failure_domain("host-a").unwrap();
        node.configure_failure_domain("host-a").unwrap();
        assert!(node.configure_failure_domain("host-b").is_err());
    }

    #[test]
    fn recovered_guild_retry_merges_endpoint_churn() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, first_peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path(), local_seed).unwrap();
        node.adopt_recovered_guild(certificate.clone(), first_peers.clone())
            .unwrap();

        let mut changed_peers = first_peers.clone();
        let changed_member = changed_peers[0].member.node_id;
        let changed_endpoint = format!(
            "/ip4/127.0.0.1/udp/42000/quic-v1/p2p/{}",
            changed_member.libp2p_peer_id().unwrap()
        );
        changed_peers[0].endpoints = vec![changed_endpoint.clone()];
        node.adopt_recovered_guild(certificate.clone(), changed_peers)
            .unwrap();
        let changed_summary = node.guild_summary().unwrap().unwrap();
        assert_eq!(
            changed_summary
                .peers
                .iter()
                .find(|peer| peer.member.node_id == changed_member)
                .unwrap()
                .endpoints
                .as_slice(),
            std::slice::from_ref(&changed_endpoint)
        );

        let unavailable_peers = first_peers
            .into_iter()
            .map(|mut peer| {
                peer.endpoints.clear();
                peer
            })
            .collect();
        node.adopt_recovered_guild(certificate, unavailable_peers)
            .unwrap();
        let resumed_summary = node.guild_summary().unwrap().unwrap();
        assert_eq!(
            resumed_summary
                .peers
                .iter()
                .find(|peer| peer.member.node_id == changed_member)
                .unwrap()
                .endpoints
                .as_slice(),
            std::slice::from_ref(&changed_endpoint)
        );
    }

    #[test]
    fn prepared_revision_pages_are_bound_to_the_requested_guild() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([88; 32])).unwrap();
        let guild_id = [87; 32];
        let revision_id = Uuid::from_bytes([86; 16]);
        let revision = SignedRecord::sign(
            b"mutualbackup/user-revision/v1",
            UserRevision {
                format_version: 1,
                guild_id,
                cipher_profile: mb_core::V1_CIPHER_PROFILE,
                revision_id,
                owner: node.keys().node_id(),
                sequence: 1,
                parent: None,
                metadata_sectors: Vec::new(),
                data_sectors: Vec::new(),
            },
            node.keys(),
        )
        .unwrap();
        node.control
            .put_record(
                "user-revision",
                revision_id.as_bytes(),
                &canonical_bytes(&revision).unwrap(),
            )
            .unwrap();
        let reader = node.reader_config().open().unwrap();
        assert!(
            reader
                .prepared_revision_page(&guild_id, revision_id, 0)
                .is_ok()
        );
        assert!(
            reader
                .prepared_revision_page(&[85; 32], revision_id, 0)
                .is_err()
        );
    }

    #[test]
    fn recovery_publication_sequence_is_durable_and_not_a_checkpoint_generation() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([84; 32]);
        let slot = [83; 32];
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.next_recovery_publication_sequence(&slot, 1).unwrap(),
            1
        );
        assert_eq!(
            node.next_recovery_publication_sequence(&slot, 1).unwrap(),
            2
        );
        drop(node);
        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened
                .next_recovery_publication_sequence(&slot, 9)
                .unwrap(),
            9
        );
    }

    #[test]
    fn parity_publication_requires_the_declared_rs_equation() {
        let temp = tempfile::tempdir().unwrap();
        let identities = (0_u8..5)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 92; 32])).node_id())
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), Seed::from_bytes([95; 32])).unwrap();
        assert_eq!(node.keys().node_id(), identities[3]);
        let information = [
            vec![1; mb_core::V1_SECTOR_SIZE],
            vec![2; mb_core::V1_SECTOR_SIZE],
            vec![3; mb_core::V1_SECTOR_SIZE],
        ];
        let encoded = mb_core::encode_3_2(information.clone()).unwrap();
        let mut invalid_parity = encoded[3].clone();
        invalid_parity[0] ^= 1;
        let roles = [
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[0],
                sector: SectorRef {
                    id: [1; 32],
                    root: sector_root(&information[0]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[1],
                sector: SectorRef {
                    id: [2; 32],
                    root: sector_root(&information[1]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[2],
                sector: SectorRef {
                    id: [3; 32],
                    root: sector_root(&information[2]),
                    logical_len: 1,
                },
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: identities[3],
                row: 0,
                root: sector_root(&invalid_parity),
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: identities[4],
                row: 1,
                root: sector_root(&encoded[4]),
            }),
        ];
        let mut group = mb_core::CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id: [7; 32],
            data_shards: mb_core::V1_RS_DATA_SHARDS,
            parity_shards: mb_core::V1_RS_PARITY_SHARDS,
            shard_size: mb_core::V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let object = ParityObject {
            format_version: 1,
            guild_id: group.guild_id,
            group_id: group.id,
            shard_index: 3,
            root: sector_root(&invalid_parity),
            bytes: invalid_parity,
        };
        let checkpoint_hash = [8; 32];
        assert!(
            !node
                .recovered_shard_is_staged(
                    &checkpoint_hash,
                    &group.guild_id,
                    &group,
                    object.shard_index,
                )
                .unwrap()
        );
        node.stage_recovered_shard(
            &checkpoint_hash,
            &group.guild_id,
            &group,
            object.shard_index,
            &object.bytes,
        )
        .unwrap();
        assert!(
            node.recovered_shard_is_staged(
                &checkpoint_hash,
                &group.guild_id,
                &group,
                object.shard_index,
            )
            .unwrap()
        );
        let mut conflicting_group = group.clone();
        let mut conflicting_bytes = object.bytes.clone();
        conflicting_bytes[0] ^= 2;
        let ShardRole::Parity(conflicting_role) = &mut conflicting_group.roles[3] else {
            unreachable!();
        };
        conflicting_role.root = sector_root(&conflicting_bytes);
        assert!(
            node.stage_recovered_shard(
                &checkpoint_hash,
                &group.guild_id,
                &conflicting_group,
                object.shard_index,
                &conflicting_bytes,
            )
            .is_err()
        );
        assert!(
            node.publish_verified_parity(&group, &information, &object)
                .is_err()
        );
        assert!(node.parity(&group.id, 3).is_err());
    }

    #[test]
    fn published_restore_requires_its_durable_ownership_marker() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([111; 32]);
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        let target = temp.path().join("restored");
        fs::create_dir(&target).unwrap();
        let checkpoint_hash = [112; 32];
        let guild_id = [113; 32];
        let revision_id = Uuid::from_bytes([114; 16]);
        let marker_name = format!(
            ".mutualbackup-recovery-ownership-{}",
            Uuid::from_bytes([115; 16])
        );
        let ownership_marker = [116; 32];
        let job = RecoveryJob {
            format_version: 2,
            guild_id,
            revision_id,
            target: target.clone(),
            staging: temp.path().join("staging"),
            staged_native_id: Some(legacy_native_directory_id(&target).unwrap()),
            marker_name: marker_name.clone(),
            ownership_marker,
            state: RecoveryJobState::Ready,
        };
        node.control
            .put_record(
                "recovery-job",
                &checkpoint_hash,
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();
        let revision = SignedRecord::sign(
            b"mutualbackup/user-revision/v1",
            UserRevision {
                format_version: 1,
                guild_id,
                cipher_profile: mb_core::V1_CIPHER_PROFILE,
                revision_id,
                owner: node.keys().node_id(),
                sequence: 1,
                parent: None,
                metadata_sectors: Vec::new(),
                data_sectors: Vec::new(),
            },
            node.keys(),
        )
        .unwrap();

        assert!(
            node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
                .is_err()
        );
        install_recovery_marker(&target, &marker_name, &ownership_marker).unwrap();
        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
        assert!(!target.join(marker_name).exists());
        let bytes = node
            .control
            .get_record("recovery-job", &checkpoint_hash)
            .unwrap()
            .unwrap();
        let completed: RecoveryJob = decode_canonical(&bytes).unwrap();
        assert_eq!(completed.state, RecoveryJobState::Complete);

        let mut interrupted_finalization = completed;
        interrupted_finalization.state = RecoveryJobState::Published;
        node.control
            .put_record(
                "recovery-job",
                &checkpoint_hash,
                &canonical_bytes(&interrupted_finalization).unwrap(),
            )
            .unwrap();
        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
        let bytes = node
            .control
            .get_record("recovery-job", &checkpoint_hash)
            .unwrap()
            .unwrap();
        let completed_again: RecoveryJob = decode_canonical(&bytes).unwrap();
        assert_eq!(completed_again.state, RecoveryJobState::Complete);
    }

    #[test]
    fn superseded_recovery_removes_only_its_owned_hidden_tree() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path().join("node"), Seed::from_bytes([117; 32])).unwrap();
        let target = temp.path().join("restored");
        let staging = temp.path().join(format!(
            ".mutualbackup-restore-{}",
            Uuid::from_bytes([118; 16])
        ));
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("partial"), b"partial restore").unwrap();
        let marker_name = format!(
            ".mutualbackup-recovery-ownership-{}",
            Uuid::from_bytes([119; 16])
        );
        let ownership_marker = [120; 32];
        install_recovery_marker(temp.path(), &marker_name, &ownership_marker).unwrap();
        let job = RecoveryJob {
            format_version: 5,
            guild_id: [121; 32],
            revision_id: Uuid::from_bytes([122; 16]),
            target: target.clone(),
            staging: staging.clone(),
            staged_native_id: Some(native_directory_id(&staging).unwrap()),
            marker_name: marker_name.clone(),
            ownership_marker,
            state: RecoveryJobState::Building,
        };

        node.remove_superseded_recovery_job(&job).unwrap();

        assert!(!staging.exists());
        assert!(!temp.path().join(marker_name).exists());
        assert!(!target.exists());
    }
}
