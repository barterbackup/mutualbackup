use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use libp2p::core::transport::ListenerId;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::behaviour::{FromSwarm, NewExternalAddrCandidate};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, StreamProtocol, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, dcutr, identify, kad, noise, ping, relay,
    request_response, yamux,
};
use tokio::sync::{Semaphore, mpsc, oneshot};

use mb_core::{
    CodingGroup, GuildCheckpoint, GuildGenesis, GuildInvite, InformationRole, Member,
    MemberSignature, NodeId, ParityRole, QuorumCheckpoint, QuorumGuildGenesis,
    RECOVERY_LOCATOR_DOMAIN, STORAGE_ACKNOWLEDGEMENT_DOMAIN, SectorId, SectorRef, ShardRole,
    SignedRecord, StorageAcknowledgement, UserRevision, V1_CATALOG_PAGE_BYTES,
    V1_MAX_CATALOG_BYTES, V1_MAX_CATALOG_PAGES, V1_MAX_CODING_GROUPS, V1_RS_DATA_SHARDS,
    V1_RS_PARITY_SHARDS, V1_SECTOR_SIZE, canonical_bytes, decode_canonical, encode_3_2,
    open_recovery_record, sector_root,
};
use mb_store::ParityObject;
use uuid::Uuid;

use crate::node::{GuildPhase, SnapshotInfo};

use super::{
    BackupDescriptor, BackupJob, CheckpointObjectKind, DhtSequenceFloors, GuildPeer,
    MAX_PEER_FRAME_BYTES, Node, NodeServerConfig, NodeService, PEER_RESPONSE_DOMAIN, PeerRequest,
    PeerRequestEnvelope, PeerResponse, PeerResponseEnvelope, checked_catalog_page_count,
    make_peer_request, peer_error_response, process_peer_request, storage_operation_id,
};

const P2P_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/peer/1");
const IDENTIFY_PROTOCOL: &str = "/mutualbackup/identify/1";
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/kad/1");
const COMMAND_CAPACITY: usize = 128;
const DHT_TTL: Duration = Duration::from_secs(15 * 60);
const DHT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DHT_MAX_PACKET_BYTES: usize = 128 * 1024;
const BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const RELAY_RESERVATION_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_RETIREMENT_GRACE: Duration = Duration::from_millis(500);
const RELAY_RETIREMENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const LEARNED_ENDPOINT_EXPIRY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_DHT_RECORDS_PER_QUERY: usize = 64;
const MAX_DHT_PROVIDERS_PER_QUERY: usize = 64;
const MAX_LEARNED_ENDPOINT_PEERS: usize = 1_024;
const MAX_ENDPOINTS_PER_PEER: usize = 8;
const MAX_RELAY_RESERVATIONS: usize = 5;
const MAX_RELAY_CIRCUITS: usize = 8;
const MAX_RELAY_CIRCUIT_BYTES: u64 = 8 * 1024 * 1024;
const SHARD_FETCH_ATTEMPTS: usize = 3;

type RelayMembers = Arc<RwLock<BTreeSet<PeerId>>>;

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub external_addresses: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub relay_reservation_addresses: Vec<Multiaddr>,
    pub enable_dht_maintenance: bool,
    pub enable_relay_server: bool,
    pub enable_hole_punching: bool,
    pub public_endpoint: String,
    pub failure_domain: String,
    pub configure_failure_domain: bool,
    pub max_connections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pPeerProfile {
    pub member: Member,
    pub endpoint: String,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum P2pPath {
    Direct,
    Relayed,
    HolePunched,
    RelayFallback,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pPeerStatus {
    pub peer_id: String,
    pub active_paths: Vec<P2pPath>,
    pub last_application_path: Option<P2pPath>,
    pub application_bytes_sent: u64,
    pub application_bytes_received: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pStatus {
    pub peer_id: String,
    pub network_ready: bool,
    pub direct_listeners_configured: usize,
    pub direct_listeners_active: usize,
    pub relay_reservations_configured: usize,
    pub relay_reservations_active: usize,
    pub degraded: Vec<String>,
    pub listen_addresses: Vec<String>,
    pub advertised_addresses: Vec<String>,
    pub peers: Vec<P2pPeerStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pStartup {
    pub direct_listeners_active: usize,
    pub relay_reservations_active: usize,
    pub degraded: Vec<String>,
}

pub type P2pStartupReceiver = oneshot::Receiver<std::result::Result<P2pStartup, String>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRecord {
    pub publisher: Option<String>,
    pub value: Vec<u8>,
}

#[derive(Clone)]
pub struct P2pClient {
    local_peer_id: PeerId,
    commands: mpsc::Sender<Command>,
}

pub struct P2pEventLoop {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    inbound_results: mpsc::Receiver<InboundResult>,
    inbound_sender: mpsc::Sender<InboundResult>,
    inbound_permits: Arc<Semaphore>,
    pending_requests: HashMap<request_response::OutboundRequestId, PendingRequest>,
    active_inbound_requests: HashMap<request_response::InboundRequestId, PeerId>,
    pending_response_bytes: HashMap<request_response::InboundRequestId, (PeerId, u64)>,
    pending_dht: HashMap<kad::QueryId, PendingDht>,
    service: Arc<NodeService>,
    server_config: NodeServerConfig,
    advertised_addresses: Vec<Multiaddr>,
    direct_listeners: HashMap<ListenerId, Multiaddr>,
    active_direct_listeners: HashSet<ListenerId>,
    closed_direct_listeners: HashSet<ListenerId>,
    bootstrap_addresses: Vec<Multiaddr>,
    enable_dht_maintenance: bool,
    bootstrap_retry: tokio::time::Interval,
    relay_reservations: Vec<Multiaddr>,
    relay_listeners: HashMap<ListenerId, Multiaddr>,
    active_relay_listeners: HashSet<ListenerId>,
    relay_retry: tokio::time::Interval,
    relay_retirement: HashMap<ConnectionId, (PeerId, tokio::time::Instant)>,
    relay_retirement_tick: tokio::time::Interval,
    relay_members: RelayMembers,
    persistent_addresses: HashMap<PeerId, BTreeSet<Multiaddr>>,
    learned_addresses: HashMap<PeerId, LearnedAddresses>,
    learned_endpoint_expiry: tokio::time::Interval,
    connection_paths: HashMap<ConnectionId, (PeerId, P2pPath)>,
    last_application_paths: HashMap<PeerId, P2pPath>,
    transfer_counters: HashMap<PeerId, TransferCounters>,
    startup_sender: Option<oneshot::Sender<std::result::Result<P2pStartup, String>>>,
    startup_receiver: Option<P2pStartupReceiver>,
    fatal_error: Option<String>,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    peer: request_response::cbor::Behaviour<
        SignedRecord<PeerRequestEnvelope>,
        SignedRecord<PeerResponseEnvelope>,
    >,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
    limits: libp2p::connection_limits::Behaviour,
}

enum Command {
    AddAddress {
        peer: PeerId,
        address: Multiaddr,
        response: oneshot::Sender<Result<()>>,
    },
    ReplaceLearnedAddresses {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
        response: oneshot::Sender<Result<()>>,
    },
    SetRelayMembers {
        members: BTreeSet<PeerId>,
        response: oneshot::Sender<Result<()>>,
    },
    Request {
        peer: PeerId,
        recipient: NodeId,
        request: Box<PeerRequest>,
        response: oneshot::Sender<Result<PeerResponse>>,
    },
    Status {
        response: oneshot::Sender<P2pStatus>,
    },
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },
    GetRecord {
        key: Vec<u8>,
        response: oneshot::Sender<Result<Vec<DhtRecord>>>,
    },
    StartProviding {
        key: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },
    GetProviders {
        key: Vec<u8>,
        response: oneshot::Sender<Result<Vec<String>>>,
    },
    Shutdown,
}

struct PendingRequest {
    peer: PeerId,
    recipient: NodeId,
    response_recipient: NodeId,
    request_id: [u8; 16],
    request_hash: [u8; 32],
    request_bytes: u64,
    response: oneshot::Sender<Result<PeerResponse>>,
}

struct InboundResult {
    peer: PeerId,
    request_id: request_response::InboundRequestId,
    channel: request_response::ResponseChannel<SignedRecord<PeerResponseEnvelope>>,
    response: Result<SignedRecord<PeerResponseEnvelope>>,
}

struct LearnedAddresses {
    addresses: BTreeSet<Multiaddr>,
    expires_at: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct TransferCounters {
    sent: u64,
    received: u64,
}

enum PendingDht {
    Put(oneshot::Sender<Result<()>>),
    Get {
        records: Vec<DhtRecord>,
        response: oneshot::Sender<Result<Vec<DhtRecord>>>,
    },
    Provide(oneshot::Sender<Result<()>>),
    Providers {
        providers: BTreeSet<String>,
        response: oneshot::Sender<Result<Vec<String>>>,
    },
}

fn guild_relay_admission(members: RelayMembers) -> Box<dyn relay::RateLimiter> {
    Box::new(
        move |peer: PeerId, _address: &Multiaddr, _now: std::time::Instant| {
            let Ok(members) = members.read() else {
                return false;
            };
            let admitted = members.contains(&peer);
            tracing::debug!(%peer, admitted, "relay guild admission decision");
            admitted
        },
    )
}

fn peer_codec() -> request_response::cbor::codec::Codec<
    SignedRecord<PeerRequestEnvelope>,
    SignedRecord<PeerResponseEnvelope>,
> {
    request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(MAX_PEER_FRAME_BYTES as u64)
        .set_response_size_maximum(MAX_PEER_FRAME_BYTES as u64)
}

fn cbor_wire_len<T: serde::Serialize>(value: &T) -> Result<u64> {
    let bytes = cbor4ii::serde::to_vec(Vec::new(), value)
        .map_err(|error| anyhow::anyhow!("CBOR size accounting failed: {error}"))?;
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

fn retry_interval(period: Duration) -> tokio::time::Interval {
    tokio::time::interval_at(tokio::time::Instant::now() + period, period)
}

fn merge_established_path(
    recorded: Option<P2pPath>,
    generic: P2pPath,
    peer_has_hole_punch: bool,
) -> P2pPath {
    match (recorded, generic, peer_has_hole_punch) {
        (Some(P2pPath::HolePunched), _, _) | (_, P2pPath::Direct, true) => P2pPath::HolePunched,
        _ => generic,
    }
}

pub fn build_p2p(node: Arc<Mutex<Node>>, config: P2pConfig) -> Result<(P2pClient, P2pEventLoop)> {
    if config.listen_addresses.is_empty() && config.relay_reservation_addresses.is_empty()
        || config.configure_failure_domain && config.failure_domain.is_empty()
        || config.max_connections == 0
    {
        bail!("invalid libp2p configuration");
    }
    let (identity, reader_config, relay_member_ids) = {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        if config.configure_failure_domain {
            node.configure_failure_domain(&config.failure_domain)?;
        }
        let relay_member_ids = node
            .guild_summary()?
            .filter(|guild| guild.phase == GuildPhase::Active)
            .into_iter()
            .flat_map(|guild| guild.peers)
            .filter_map(|peer| peer.member.node_id.libp2p_peer_id().ok())
            .collect();
        (
            node.keys().libp2p_keypair(),
            node.reader_config(),
            relay_member_ids,
        )
    };
    let relay_members = Arc::new(RwLock::new(relay_member_ids));
    let local_peer_id = identity.public().to_peer_id();
    let relay_server_enabled = config.enable_relay_server;
    let hole_punching_enabled = config.enable_hole_punching;
    let max_connections =
        u32::try_from(config.max_connections).context("libp2p connection limit exceeds u32")?;
    let mut relay_config = relay::Config {
        max_reservations: MAX_RELAY_RESERVATIONS,
        max_reservations_per_peer: 1,
        reservation_duration: Duration::from_secs(15 * 60),
        max_circuits: MAX_RELAY_CIRCUITS,
        max_circuits_per_peer: 2,
        max_circuit_duration: Duration::from_secs(2 * 60),
        max_circuit_bytes: MAX_RELAY_CIRCUIT_BYTES,
        ..relay::Config::default()
    };
    relay_config
        .reservation_rate_limiters
        .push(guild_relay_admission(relay_members.clone()));
    relay_config
        .circuit_src_rate_limiters
        .push(guild_relay_admission(relay_members.clone()));
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(move |key, relay_client| {
            let peer_id = key.public().to_peer_id();
            let mut kad_config = kad::Config::new(KAD_PROTOCOL);
            kad_config
                .set_query_timeout(Duration::from_secs(30))
                .set_replication_factor(NonZeroUsize::new(3).expect("three is nonzero"))
                .set_record_ttl(Some(DHT_TTL))
                .set_publication_interval(Some(DHT_REPUBLISH_INTERVAL))
                .set_provider_record_ttl(Some(DHT_TTL))
                .set_provider_publication_interval(Some(DHT_REPUBLISH_INTERVAL))
                .set_max_packet_size(DHT_MAX_PACKET_BYTES);
            let mut kademlia =
                kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);
            kademlia.set_mode(Some(kad::Mode::Server));
            Behaviour {
                peer: request_response::cbor::Behaviour::with_codec(
                    peer_codec(),
                    [(P2P_PROTOCOL, request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(20)),
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL.to_owned(),
                    key.public(),
                )),
                kademlia,
                relay_client,
                relay_server: Toggle::from(
                    relay_server_enabled.then(|| relay::Behaviour::new(peer_id, relay_config)),
                ),
                dcutr: Toggle::from(hole_punching_enabled.then(|| dcutr::Behaviour::new(peer_id))),
                autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                ping: ping::Behaviour::new(ping::Config::new()),
                limits: libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(max_connections))
                        .with_max_pending_outgoing(Some(max_connections))
                        .with_max_established_incoming(Some(max_connections))
                        .with_max_established(Some(max_connections))
                        .with_max_established_per_peer(Some(4)),
                ),
            }
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let mut direct_listeners = HashMap::new();
    for address in &config.listen_addresses {
        let listener = swarm
            .listen_on(address.clone())
            .with_context(|| format!("cannot listen on {address}"))?;
        direct_listeners.insert(listener, address.clone());
    }
    for address in &config.external_addresses {
        // DCUtR currently learns dial candidates from
        // `NewExternalAddrCandidate`, not `ExternalAddrConfirmed`. Feeding the
        // configured address through that lifecycle first also avoids Swarm's
        // suppression of a later, identical Identify observation.
        swarm
            .behaviour_mut()
            .on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate { addr: address },
            ));
        swarm.add_external_address(address.clone());
    }
    let mut persistent_addresses = HashMap::<PeerId, BTreeSet<Multiaddr>>::new();
    for address in &config.bootstrap_addresses {
        let (peer, normalized) = add_address_to_swarm(&mut swarm, address.clone())?;
        persistent_addresses
            .entry(peer)
            .or_default()
            .insert(normalized);
        if let Err(error) = swarm.dial(address.clone()) {
            tracing::warn!(%address, %error, "initial libp2p dial was rejected");
        }
    }
    let mut relay_reservations = Vec::new();
    let mut relay_listeners = HashMap::new();
    for address in &config.relay_reservation_addresses {
        let (peer, normalized) = add_address_to_swarm(&mut swarm, address.clone())?;
        persistent_addresses
            .entry(peer)
            .or_default()
            .insert(normalized);
        let reservation = address
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        let listener = swarm
            .listen_on(reservation.clone())
            .with_context(|| format!("cannot request relay reservation through {reservation}"))?;
        relay_reservations.push(reservation.clone());
        relay_listeners.insert(listener, reservation);
    }
    if config.enable_dht_maintenance
        && !config.bootstrap_addresses.is_empty()
        && let Err(error) = swarm.behaviour_mut().kademlia.bootstrap()
    {
        tracing::warn!(%error, "initial Kademlia bootstrap could not start");
    }

    let local_node_id = reader_config.keys().node_id();
    let service = Arc::new(NodeService {
        writer: node,
        reader_config,
        readers: Mutex::new(Vec::new()),
        max_readers: config.max_connections,
        active_readers: std::sync::atomic::AtomicUsize::new(0),
    });
    let server_config = NodeServerConfig {
        #[cfg(test)]
        listen: "127.0.0.1:1".parse().expect("constant socket address"),
        public_endpoint: config.public_endpoint,
        failure_domain: config.failure_domain,
        trusted_coordinator: local_node_id,
        #[cfg(test)]
        max_connections: config.max_connections,
    };
    let (command_sender, command_receiver) = mpsc::channel(COMMAND_CAPACITY);
    let (inbound_sender, inbound_results) = mpsc::channel(COMMAND_CAPACITY);
    let (startup_sender, startup_receiver) = oneshot::channel();
    Ok((
        P2pClient {
            local_peer_id,
            commands: command_sender,
        },
        P2pEventLoop {
            swarm,
            commands: command_receiver,
            inbound_results,
            inbound_sender,
            inbound_permits: Arc::new(Semaphore::new(config.max_connections)),
            pending_requests: HashMap::new(),
            active_inbound_requests: HashMap::new(),
            pending_response_bytes: HashMap::new(),
            pending_dht: HashMap::new(),
            service,
            server_config,
            advertised_addresses: config.external_addresses,
            direct_listeners,
            active_direct_listeners: HashSet::new(),
            closed_direct_listeners: HashSet::new(),
            bootstrap_addresses: config.bootstrap_addresses,
            enable_dht_maintenance: config.enable_dht_maintenance,
            bootstrap_retry: retry_interval(BOOTSTRAP_RETRY_INTERVAL),
            relay_reservations,
            relay_listeners,
            active_relay_listeners: HashSet::new(),
            relay_retry: retry_interval(RELAY_RESERVATION_RETRY_INTERVAL),
            relay_retirement: HashMap::new(),
            relay_retirement_tick: retry_interval(RELAY_RETIREMENT_POLL_INTERVAL),
            relay_members,
            persistent_addresses,
            learned_addresses: HashMap::new(),
            learned_endpoint_expiry: retry_interval(LEARNED_ENDPOINT_EXPIRY_INTERVAL),
            connection_paths: HashMap::new(),
            last_application_paths: HashMap::new(),
            transfer_counters: HashMap::new(),
            startup_sender: Some(startup_sender),
            startup_receiver: Some(startup_receiver),
            fatal_error: None,
        },
    ))
}

impl P2pClient {
    pub fn local_peer_id(&self) -> String {
        self.local_peer_id.to_string()
    }

    pub async fn add_peer_address(&self, peer: NodeId, address: Multiaddr) -> Result<()> {
        let peer = peer.libp2p_peer_id()?;
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::AddAddress {
                peer,
                address,
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("libp2p address command was lost")?
    }

    async fn replace_learned_peer_addresses(
        &self,
        peer: NodeId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
    ) -> Result<()> {
        let peer = peer.libp2p_peer_id()?;
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::ReplaceLearnedAddresses {
                peer,
                addresses,
                expires_at_unix_seconds,
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p learned-address command was lost")?
    }

    async fn set_relay_members(&self, members: BTreeSet<PeerId>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::SetRelayMembers { members, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p relay-membership command was lost")?
    }

    pub async fn profile(&self, peer: NodeId) -> Result<P2pPeerProfile> {
        let response = self.call(peer, PeerRequest::Profile).await?;
        let PeerResponse::Profile(profile) = response else {
            bail!("peer returned the wrong response to profile request");
        };
        Ok(P2pPeerProfile {
            member: profile.member,
            endpoint: profile.endpoint,
        })
    }

    pub async fn join_guild(
        &self,
        coordinator: NodeId,
        invite: SignedRecord<GuildInvite>,
        peer: GuildPeer,
    ) -> Result<()> {
        let response = self
            .call(
                coordinator,
                PeerRequest::JoinGuild {
                    invite: Box::new(invite),
                    peer,
                },
            )
            .await?;
        if !matches!(response, PeerResponse::Ack) {
            bail!("peer returned the wrong response to guild join request");
        }
        Ok(())
    }

    pub async fn propose_guild_genesis(
        &self,
        peer: NodeId,
        genesis: GuildGenesis,
    ) -> Result<MemberSignature> {
        let response = self
            .call(
                peer,
                PeerRequest::ProposeGuildGenesis {
                    genesis: Box::new(genesis),
                },
            )
            .await?;
        let PeerResponse::GuildGenesisSignature(signature) = response else {
            bail!("peer returned the wrong response to guild genesis proposal");
        };
        Ok(signature)
    }

    pub async fn install_guild_genesis(
        &self,
        peer: NodeId,
        certificate: QuorumGuildGenesis,
        peers: Vec<GuildPeer>,
    ) -> Result<()> {
        let response = self
            .call(
                peer,
                PeerRequest::InstallGuildGenesis {
                    certificate: Box::new(certificate),
                    peers,
                },
            )
            .await?;
        if !matches!(response, PeerResponse::Ack) {
            bail!("peer returned the wrong response to guild genesis installation");
        }
        Ok(())
    }

    pub async fn submit_backup(
        &self,
        coordinator: NodeId,
        descriptor: BackupDescriptor,
    ) -> Result<BackupJob> {
        let response = self
            .call(coordinator, PeerRequest::SubmitBackup { descriptor })
            .await?;
        let PeerResponse::BackupJob(job) = response else {
            bail!("peer returned the wrong response to backup submission");
        };
        Ok(job)
    }

    pub async fn backup_status(
        &self,
        coordinator: NodeId,
        guild_id: [u8; 32],
        revision_id: Uuid,
    ) -> Result<BackupJob> {
        let response = self
            .call(
                coordinator,
                PeerRequest::BackupStatus {
                    guild_id,
                    revision_id,
                },
            )
            .await?;
        let PeerResponse::BackupJob(job) = response else {
            bail!("peer returned the wrong response to backup status request");
        };
        Ok(job)
    }

    pub(crate) async fn prepared_revision_page(
        &self,
        owner: NodeId,
        guild_id: [u8; 32],
        revision_id: Uuid,
        page_index: u32,
    ) -> Result<(u32, [u8; 32], Vec<u8>)> {
        let response = self
            .call(
                owner,
                PeerRequest::GetPreparedRevisionPage {
                    guild_id,
                    revision_id,
                    page_index,
                },
            )
            .await?;
        let PeerResponse::PreparedRevisionPage {
            total_pages,
            page_hash,
            bytes,
        } = response
        else {
            bail!("peer returned the wrong prepared revision page response");
        };
        Ok((total_pages, page_hash, bytes))
    }

    pub(crate) async fn sector(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        sector_id: SectorId,
    ) -> Result<Vec<u8>> {
        let response = self
            .call(
                peer,
                PeerRequest::GetSector {
                    guild_id,
                    sector_id,
                },
            )
            .await?;
        let PeerResponse::Bytes(bytes) = response else {
            bail!("peer returned the wrong sector response");
        };
        Ok(bytes)
    }

    pub(crate) async fn parity(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>> {
        let response = self
            .call(
                peer,
                PeerRequest::GetParity {
                    guild_id,
                    group_id,
                    shard_index,
                },
            )
            .await?;
        let PeerResponse::Bytes(bytes) = response else {
            bail!("peer returned the wrong parity response");
        };
        Ok(bytes)
    }

    pub(crate) async fn guild_genesis(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
    ) -> Result<QuorumGuildGenesis> {
        let response = self
            .call(peer, PeerRequest::GetGuildGenesis { guild_id })
            .await?;
        let PeerResponse::GuildGenesis(certificate) = response else {
            bail!("peer returned the wrong guild genesis response");
        };
        certificate.verify()?;
        Ok(*certificate)
    }

    pub(crate) async fn checkpoint_page(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        page_index: u32,
    ) -> Result<(u32, [u8; 32], Vec<u8>)> {
        let response = self
            .call(
                peer,
                PeerRequest::GetCheckpointPage {
                    guild_id,
                    checkpoint_hash,
                    page_index,
                },
            )
            .await?;
        let PeerResponse::CheckpointPage {
            total_pages,
            page_hash,
            bytes,
        } = response
        else {
            bail!("peer returned the wrong checkpoint page response");
        };
        Ok((total_pages, page_hash, bytes))
    }

    pub(crate) async fn ensure_filler(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        revision_id: Uuid,
        ordinal: u64,
    ) -> Result<(SectorRef, Vec<u8>)> {
        let response = self
            .call(
                peer,
                PeerRequest::EnsureFiller {
                    guild_id,
                    revision_id,
                    ordinal,
                },
            )
            .await?;
        let PeerResponse::Filler { reference, bytes } = response else {
            bail!("peer returned the wrong filler response");
        };
        Ok((reference, bytes))
    }

    pub(crate) async fn publish_parity(
        &self,
        peer: NodeId,
        group: CodingGroup,
        information: [Vec<u8>; 3],
        object: ParityObject,
    ) -> Result<SignedRecord<StorageAcknowledgement>> {
        let operation_id = storage_operation_id(&group.id, object.shard_index);
        let response = self
            .call(
                peer,
                PeerRequest::PublishParity {
                    operation_id,
                    group: Box::new(group),
                    information,
                    object,
                },
            )
            .await?;
        let PeerResponse::StorageAcknowledgement(acknowledgement) = response else {
            bail!("peer returned the wrong parity publication response");
        };
        acknowledgement.verify(STORAGE_ACKNOWLEDGEMENT_DOMAIN)?;
        acknowledgement.value.validate()?;
        if acknowledgement.value.operation_id != operation_id {
            bail!("parity acknowledgement has the wrong operation identity");
        }
        Ok(acknowledgement)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn put_checkpoint_page(
        &self,
        peer: NodeId,
        object_kind: CheckpointObjectKind,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        page_index: u32,
        total_pages: u32,
        page_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> Result<()> {
        let response = self
            .call(
                peer,
                PeerRequest::PutCheckpointPage {
                    object_kind,
                    guild_id,
                    checkpoint_hash,
                    page_index,
                    total_pages,
                    page_hash,
                    bytes,
                },
            )
            .await?;
        if !matches!(response, PeerResponse::Ack) {
            bail!("peer returned the wrong checkpoint page response");
        }
        Ok(())
    }

    pub(crate) async fn sign_checkpoint(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    ) -> Result<MemberSignature> {
        let response = self
            .call(
                peer,
                PeerRequest::SignCheckpoint {
                    guild_id,
                    checkpoint_hash,
                },
            )
            .await?;
        let PeerResponse::CheckpointSignature(signature) = response else {
            bail!("peer returned the wrong checkpoint signature response");
        };
        Ok(signature)
    }

    pub(crate) async fn finalize_checkpoint(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let response = self
            .call(
                peer,
                PeerRequest::FinalizeCheckpoint {
                    guild_id,
                    checkpoint_hash,
                },
            )
            .await?;
        if !matches!(response, PeerResponse::Ack) {
            bail!("peer returned the wrong checkpoint finalization response");
        }
        Ok(())
    }

    pub async fn status(&self) -> Result<P2pStatus> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::Status { response })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("libp2p status command was lost")
    }

    pub async fn put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::PutRecord {
                key,
                value,
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("DHT put command was lost")?
    }

    pub async fn get_record(&self, key: Vec<u8>) -> Result<Vec<DhtRecord>> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::GetRecord { key, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("DHT get command was lost")?
    }

    pub async fn start_providing(&self, key: Vec<u8>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::StartProviding { key, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("DHT provide command was lost")?
    }

    pub async fn get_providers(&self, key: Vec<u8>) -> Result<Vec<String>> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::GetProviders { key, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("DHT provider command was lost")?
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.commands
            .send(Command::Shutdown)
            .await
            .context("libp2p event loop stopped")
    }

    async fn call(&self, peer: NodeId, request: PeerRequest) -> Result<PeerResponse> {
        let expected_peer_id = peer.libp2p_peer_id()?;
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::Request {
                peer: expected_peer_id,
                recipient: peer,
                request: Box::new(request),
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("libp2p request command was lost")?
    }
}

impl P2pEventLoop {
    pub fn take_startup_receiver(&mut self) -> Result<P2pStartupReceiver> {
        self.startup_receiver
            .take()
            .context("libp2p startup receiver was already taken")
    }

    pub async fn run(mut self) -> Result<()> {
        drop(self.startup_receiver.take());
        let result = self.run_inner().await;
        if let Err(error) = &result {
            self.fail_startup(format!("{error:#}"));
        }
        result
    }

    async fn run_inner(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(command) = self.commands.recv() => {
                    if self.handle_command(command)? {
                        return Ok(());
                    }
                }
                Some(result) = self.inbound_results.recv() => {
                    match result.response {
                        Ok(response) => {
                            let response_bytes = cbor_wire_len(&response).ok();
                            if self
                                .swarm
                                .behaviour_mut()
                                .peer
                                .send_response(result.channel, response)
                                .is_err()
                            {
                                self.active_inbound_requests.remove(&result.request_id);
                                tracing::warn!("peer disconnected before its response was ready");
                            } else if let Some(response_bytes) = response_bytes {
                                self.pending_response_bytes.insert(
                                    result.request_id,
                                    (result.peer, response_bytes),
                                );
                            }
                        }
                        Err(error) => {
                            self.active_inbound_requests.remove(&result.request_id);
                            tracing::warn!(%error, "peer request worker failed");
                        }
                    }
                }
                _ = self.bootstrap_retry.tick(), if !self.bootstrap_addresses.is_empty() => {
                    self.retry_bootstrap();
                }
                _ = self.relay_retry.tick(), if !self.relay_reservations.is_empty() => {
                    self.retry_relay_reservations();
                }
                _ = self.relay_retirement_tick.tick(), if !self.relay_retirement.is_empty() => {
                    self.retire_idle_relay_connections();
                }
                _ = self.learned_endpoint_expiry.tick(), if !self.learned_addresses.is_empty() => {
                    self.expire_learned_addresses();
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                    if let Some(error) = self.fatal_error.take() {
                        bail!(error);
                    }
                },
            }
        }
    }

    fn network_ready(&self) -> bool {
        !self.active_direct_listeners.is_empty() || !self.active_relay_listeners.is_empty()
    }

    fn transport_degradation(&self) -> Vec<String> {
        let mut degraded = Vec::new();
        if self.active_direct_listeners.len() < self.direct_listeners.len() {
            degraded.push(format!(
                "direct listeners active {}/{}",
                self.active_direct_listeners.len(),
                self.direct_listeners.len()
            ));
        }
        if self.active_relay_listeners.len() < self.relay_reservations.len() {
            degraded.push(format!(
                "relay reservations active {}/{}",
                self.active_relay_listeners.len(),
                self.relay_reservations.len()
            ));
        }
        degraded
    }

    fn complete_startup_if_ready(&mut self) {
        if !self.network_ready() {
            return;
        }
        if let Some(sender) = self.startup_sender.take() {
            let _ = sender.send(Ok(P2pStartup {
                direct_listeners_active: self.active_direct_listeners.len(),
                relay_reservations_active: self.active_relay_listeners.len(),
                degraded: self.transport_degradation(),
            }));
        }
    }

    fn fail_startup(&mut self, error: String) {
        if let Some(sender) = self.startup_sender.take() {
            let _ = sender.send(Err(error));
        }
    }

    fn retry_bootstrap(&mut self) {
        for address in &self.bootstrap_addresses {
            // A circuit address contains both the relay and destination peer
            // IDs. Connectivity to the relay does not mean the destination is
            // connected, so retries must key off the terminal identity.
            let peer = terminal_peer_id(address).ok();
            if peer.is_some_and(|peer| self.swarm.is_connected(&peer)) {
                continue;
            }
            if let Err(error) = self.swarm.dial(address.clone()) {
                tracing::debug!(%address, %error, "libp2p bootstrap retry was rejected");
            }
        }
        if self.enable_dht_maintenance
            && let Err(error) = self.swarm.behaviour_mut().kademlia.bootstrap()
        {
            tracing::debug!(%error, "Kademlia bootstrap retry could not start");
        }
    }

    fn retry_relay_reservations(&mut self) {
        for reservation in &self.relay_reservations {
            if self
                .relay_listeners
                .values()
                .any(|pending| pending == reservation)
            {
                continue;
            }
            match self.swarm.listen_on(reservation.clone()) {
                Ok(listener) => {
                    self.relay_listeners.insert(listener, reservation.clone());
                }
                Err(error) => {
                    tracing::warn!(%reservation, %error, "relay reservation retry was rejected");
                }
            }
        }
    }

    fn replace_learned_addresses(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
    ) -> Result<()> {
        if addresses.len() > MAX_ENDPOINTS_PER_PEER {
            bail!("peer published too many endpoints");
        }
        let now_unix = unix_seconds();
        if !addresses.is_empty() && expires_at_unix_seconds <= now_unix {
            bail!("peer endpoints are already expired");
        }
        if !self.learned_addresses.contains_key(&peer)
            && !addresses.is_empty()
            && self.learned_addresses.len() >= MAX_LEARNED_ENDPOINT_PEERS
        {
            bail!("learned endpoint cache is full");
        }

        let mut normalized = BTreeSet::new();
        for address in addresses {
            normalized.insert(normalize_known_address(peer, address)?);
        }
        for address in &normalized {
            self.swarm.add_peer_address(peer, address.clone());
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer, address.clone());
        }

        let previous = self.learned_addresses.remove(&peer);
        if let Some(previous) = previous {
            for address in previous.addresses.difference(&normalized) {
                let persistent = self
                    .persistent_addresses
                    .get(&peer)
                    .is_some_and(|addresses| addresses.contains(address));
                if !persistent {
                    remove_known_address(&mut self.swarm, peer, address);
                }
            }
        }
        if !normalized.is_empty() {
            let lifetime = Duration::from_secs(
                expires_at_unix_seconds
                    .saturating_sub(now_unix)
                    .min(DHT_TTL.as_secs()),
            );
            self.learned_addresses.insert(
                peer,
                LearnedAddresses {
                    addresses: normalized,
                    expires_at: tokio::time::Instant::now() + lifetime,
                },
            );
        }
        Ok(())
    }

    fn expire_learned_addresses(&mut self) {
        let now = tokio::time::Instant::now();
        let expired = self
            .learned_addresses
            .iter()
            .filter_map(|(peer, addresses)| (addresses.expires_at <= now).then_some(*peer))
            .collect::<Vec<_>>();
        for peer in expired {
            let Some(addresses) = self.learned_addresses.remove(&peer) else {
                continue;
            };
            for address in addresses.addresses {
                let persistent = self
                    .persistent_addresses
                    .get(&peer)
                    .is_some_and(|addresses| addresses.contains(&address));
                if !persistent {
                    remove_known_address(&mut self.swarm, peer, &address);
                }
            }
        }
    }

    fn handle_command(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::AddAddress {
                peer,
                address,
                response,
            } => {
                let result = add_known_address(&mut self.swarm, peer, address).map(|address| {
                    self.persistent_addresses
                        .entry(peer)
                        .or_default()
                        .insert(address);
                });
                let _ = response.send(result);
            }
            Command::ReplaceLearnedAddresses {
                peer,
                addresses,
                expires_at_unix_seconds,
                response,
            } => {
                let result =
                    self.replace_learned_addresses(peer, addresses, expires_at_unix_seconds);
                let _ = response.send(result);
            }
            Command::SetRelayMembers { members, response } => {
                let result = self
                    .relay_members
                    .write()
                    .map_err(|_| anyhow::anyhow!("relay membership lock is poisoned"))
                    .map(|mut current| *current = members);
                let _ = response.send(result);
            }
            Command::Request {
                peer,
                recipient,
                request,
                response,
            } => {
                match make_peer_request(
                    self.service.reader_config.keys(),
                    (!matches!(*request, PeerRequest::Profile)).then_some(recipient),
                    *request,
                ) {
                    Ok(request) => {
                        let request_id = request.value.request_id;
                        let request_hash = canonical_bytes(&request.value)
                            .map(|bytes| *blake3::hash(&bytes).as_bytes());
                        match request_hash {
                            Ok(request_hash) => {
                                let request_bytes = cbor_wire_len(&request).unwrap_or(0);
                                let outbound_id =
                                    self.swarm.behaviour_mut().peer.send_request(&peer, request);
                                self.pending_requests.insert(
                                    outbound_id,
                                    PendingRequest {
                                        peer,
                                        recipient,
                                        response_recipient: self
                                            .service
                                            .reader_config
                                            .keys()
                                            .node_id(),
                                        request_id,
                                        request_hash,
                                        request_bytes,
                                        response,
                                    },
                                );
                            }
                            Err(error) => {
                                let _ = response.send(Err(error.into()));
                            }
                        }
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            Command::Status { response } => {
                let mut listen_addresses = self
                    .swarm
                    .listeners()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                listen_addresses.sort();
                let mut advertised_addresses = if self.advertised_addresses.is_empty() {
                    listen_addresses.clone()
                } else {
                    let mut addresses = self
                        .advertised_addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    addresses.extend(
                        listen_addresses
                            .iter()
                            .filter(|address| address.contains("/p2p-circuit"))
                            .cloned(),
                    );
                    addresses
                };
                advertised_addresses.sort();
                advertised_addresses.dedup();
                let mut peers = self
                    .swarm
                    .connected_peers()
                    .map(|peer| {
                        let mut active_paths = self
                            .connection_paths
                            .values()
                            .filter_map(|(connected_peer, path)| {
                                (connected_peer == peer).then_some(*path)
                            })
                            .collect::<Vec<_>>();
                        active_paths.sort();
                        active_paths.dedup();
                        P2pPeerStatus {
                            peer_id: peer.to_string(),
                            active_paths,
                            last_application_path: self.last_application_paths.get(peer).copied(),
                            application_bytes_sent: self
                                .transfer_counters
                                .get(peer)
                                .map_or(0, |counter| counter.sent),
                            application_bytes_received: self
                                .transfer_counters
                                .get(peer)
                                .map_or(0, |counter| counter.received),
                        }
                    })
                    .collect::<Vec<_>>();
                peers.sort_by(|left, right| left.peer_id.cmp(&right.peer_id));
                let _ = response.send(P2pStatus {
                    peer_id: self.swarm.local_peer_id().to_string(),
                    network_ready: self.network_ready(),
                    direct_listeners_configured: self.direct_listeners.len(),
                    direct_listeners_active: self.active_direct_listeners.len(),
                    relay_reservations_configured: self.relay_reservations.len(),
                    relay_reservations_active: self.active_relay_listeners.len(),
                    degraded: self.transport_degradation(),
                    listen_addresses,
                    advertised_addresses,
                    peers,
                });
            }
            Command::PutRecord {
                key,
                value,
                response,
            } => {
                let record = kad::Record::new(kad::RecordKey::new(&key), value);
                match self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(record, kad::Quorum::One)
                {
                    Ok(id) => {
                        self.pending_dht.insert(id, PendingDht::Put(response));
                    }
                    Err(error) => {
                        let _ = response.send(Err(error.into()));
                    }
                }
            }
            Command::GetRecord { key, response } => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_record(kad::RecordKey::new(&key));
                self.pending_dht.insert(
                    id,
                    PendingDht::Get {
                        records: Vec::new(),
                        response,
                    },
                );
            }
            Command::StartProviding { key, response } => {
                match self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(kad::RecordKey::new(&key))
                {
                    Ok(id) => {
                        self.pending_dht.insert(id, PendingDht::Provide(response));
                    }
                    Err(error) => {
                        let _ = response.send(Err(error.into()));
                    }
                }
            }
            Command::GetProviders { key, response } => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(kad::RecordKey::new(&key));
                self.pending_dht.insert(
                    id,
                    PendingDht::Providers {
                        providers: BTreeSet::new(),
                        response,
                    },
                );
            }
            Command::Shutdown => return Ok(true),
        }
        Ok(false)
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Peer(event)) => self.handle_peer_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                for address in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, address);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id, result, step, ..
                },
            )) => self.handle_dht_result(id, result, step.last),
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                match &event.result {
                    Ok(connection_id) => {
                        self.connection_paths
                            .insert(*connection_id, (event.remote_peer_id, P2pPath::HolePunched));
                        // Simultaneous QUIC punching can establish a sibling
                        // inbound connection whose generic swarm event carries
                        // no DCUtR marker. Once the peer-level upgrade succeeds,
                        // both direct sides belong to the same punched session.
                        for (peer, path) in self.connection_paths.values_mut() {
                            if *peer == event.remote_peer_id && *path == P2pPath::Direct {
                                *path = P2pPath::HolePunched;
                            }
                        }
                        if self.last_application_paths.get(&event.remote_peer_id)
                            == Some(&P2pPath::Direct)
                        {
                            self.last_application_paths
                                .insert(event.remote_peer_id, P2pPath::HolePunched);
                        }
                        // request-response does not expose per-request
                        // connection selection and may otherwise keep using
                        // the older relay circuit indefinitely. Schedule only
                        // duplicate relayed sessions for retirement after
                        // DCUtR has produced a direct one. A grace period and
                        // in-flight tracking avoid cutting off the request
                        // which caused the peers to meet over the relay.
                        let relayed_connections = self
                            .connection_paths
                            .iter()
                            .filter_map(|(candidate, (peer, path))| {
                                (*peer == event.remote_peer_id
                                    && matches!(path, P2pPath::Relayed | P2pPath::RelayFallback))
                                .then_some(*candidate)
                            })
                            .collect::<Vec<_>>();
                        for relayed_connection in relayed_connections {
                            self.relay_retirement.insert(
                                relayed_connection,
                                (
                                    event.remote_peer_id,
                                    tokio::time::Instant::now() + RELAY_RETIREMENT_GRACE,
                                ),
                            );
                        }
                    }
                    Err(_) => {
                        for (peer, path) in self.connection_paths.values_mut() {
                            if *peer == event.remote_peer_id && *path == P2pPath::Relayed {
                                *path = P2pPath::RelayFallback;
                            }
                        }
                    }
                }
                tracing::info!(?event, "DCUtR event");
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => {
                tracing::info!(?event, "relay client event");
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayServer(event)) => {
                tracing::info!(?event, "relay server event");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                tracing::debug!(?event, "AutoNAT event");
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                if self.direct_listeners.contains_key(&listener_id) {
                    self.active_direct_listeners.insert(listener_id);
                }
                if self.relay_listeners.contains_key(&listener_id) {
                    self.active_relay_listeners.insert(listener_id);
                }
                self.complete_startup_if_ready();
                tracing::info!(%address, "libp2p listening");
            }
            event @ SwarmEvent::ListenerError { .. } => {
                tracing::warn!(?event, "libp2p listener failed");
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            } => {
                let direct = self.direct_listeners.contains_key(&listener_id);
                if direct {
                    self.active_direct_listeners.remove(&listener_id);
                    self.closed_direct_listeners.insert(listener_id);
                }
                if self.relay_listeners.remove(&listener_id).is_some() {
                    self.active_relay_listeners.remove(&listener_id);
                }
                let direct_exhausted = !self.direct_listeners.is_empty()
                    && self.active_direct_listeners.is_empty()
                    && self.closed_direct_listeners.len() == self.direct_listeners.len();
                if direct_exhausted && self.relay_reservations.is_empty() {
                    let error =
                        format!("all configured direct libp2p listeners closed: {reason:?}");
                    self.fail_startup(error.clone());
                    self.fatal_error = Some(error);
                }
                tracing::warn!(?listener_id, ?addresses, ?reason, "libp2p listener closed");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let path = if endpoint.is_relayed() {
                    P2pPath::Relayed
                } else {
                    P2pPath::Direct
                };
                // DCUtR may report the upgraded connection before or after the
                // generic swarm event. Do not let the latter erase the more
                // specific classification when it arrives second.
                let recorded = self
                    .connection_paths
                    .get(&connection_id)
                    .map(|(_, path)| *path);
                let peer_has_hole_punch =
                    self.connection_paths.values().any(|(connected, path)| {
                        *connected == peer_id && *path == P2pPath::HolePunched
                    });
                self.connection_paths.insert(
                    connection_id,
                    (
                        peer_id,
                        merge_established_path(recorded, path, peer_has_hole_punch),
                    ),
                );
                tracing::info!(peer = %peer_id, ?endpoint, "libp2p connection established");
            }
            SwarmEvent::ConnectionClosed {
                connection_id,
                peer_id,
                num_established,
                ..
            } => {
                self.connection_paths.remove(&connection_id);
                self.relay_retirement.remove(&connection_id);
                if !self
                    .connection_paths
                    .values()
                    .any(|(connected, path)| *connected == peer_id && *path == P2pPath::HolePunched)
                {
                    self.relay_retirement
                        .retain(|_, (candidate, _)| *candidate != peer_id);
                }
                if num_established == 0 {
                    self.last_application_paths.remove(&peer_id);
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(peer = ?peer_id, %error, "libp2p outgoing connection failed");
            }
            _ => {}
        }
    }

    fn handle_peer_event(
        &mut self,
        event: request_response::Event<
            SignedRecord<PeerRequestEnvelope>,
            SignedRecord<PeerResponseEnvelope>,
        >,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message,
            } => {
                if let Some((_, path)) = self.connection_paths.get(&connection_id) {
                    self.last_application_paths.insert(
                        peer,
                        if *path == P2pPath::Relayed {
                            P2pPath::RelayFallback
                        } else {
                            *path
                        },
                    );
                }
                match message {
                    request_response::Message::Request {
                        request,
                        channel,
                        request_id,
                    } => {
                        if let Ok(bytes) = cbor_wire_len(&request) {
                            let counter = self.transfer_counters.entry(peer).or_default();
                            counter.received = counter.received.saturating_add(bytes);
                        }
                        if request.signer.libp2p_peer_id().ok() != Some(peer) {
                            tracing::warn!(%peer, "application signer does not match libp2p peer");
                            return;
                        }
                        let service = self.service.clone();
                        let config = self.server_config.clone();
                        let sender = self.inbound_sender.clone();
                        let permit = match self.inbound_permits.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                match peer_error_response(
                                    &service,
                                    &request,
                                    crate::WireError::busy("peer request capacity is exhausted"),
                                ) {
                                    Ok(response) => {
                                        let response_bytes = cbor_wire_len(&response).ok();
                                        if self
                                            .swarm
                                            .behaviour_mut()
                                            .peer
                                            .send_response(channel, response)
                                            .is_err()
                                        {
                                            tracing::warn!(
                                                "overloaded peer disconnected before rejection"
                                            );
                                        } else if let Some(response_bytes) = response_bytes {
                                            self.active_inbound_requests.insert(request_id, peer);
                                            self.pending_response_bytes
                                                .insert(request_id, (peer, response_bytes));
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            %error,
                                            "could not encode peer overload response"
                                        );
                                    }
                                }
                                return;
                            }
                        };
                        self.active_inbound_requests.insert(request_id, peer);
                        tokio::task::spawn_blocking(move || {
                            let _permit = permit;
                            let response = process_peer_request(service, &config, request);
                            let _ = sender.blocking_send(InboundResult {
                                peer,
                                request_id,
                                channel,
                                response,
                            });
                        });
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let response_bytes = cbor_wire_len(&response).ok();
                        if let Some(pending) = self.pending_requests.remove(&request_id) {
                            if pending.peer == peer {
                                let counter = self.transfer_counters.entry(peer).or_default();
                                counter.sent = counter.sent.saturating_add(pending.request_bytes);
                                if let Some(response_bytes) = response_bytes {
                                    counter.received =
                                        counter.received.saturating_add(response_bytes);
                                }
                            }
                            let result = if pending.peer == peer {
                                validate_outbound_response(response, &pending)
                            } else {
                                Err(anyhow::anyhow!("libp2p response came from the wrong peer"))
                            };
                            let _ = pending.response.send(result);
                        }
                    }
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(pending) = self.pending_requests.remove(&request_id) {
                    let _ = pending
                        .response
                        .send(Err(anyhow::anyhow!("libp2p request failed: {error}")));
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                self.active_inbound_requests.remove(&request_id);
                self.pending_response_bytes.remove(&request_id);
                tracing::warn!(%peer, %error, "libp2p inbound request failed");
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                self.active_inbound_requests.remove(&request_id);
                if let Some((expected_peer, bytes)) =
                    self.pending_response_bytes.remove(&request_id)
                    && expected_peer == peer
                {
                    let counter = self.transfer_counters.entry(peer).or_default();
                    counter.sent = counter.sent.saturating_add(bytes);
                }
            }
        }
    }

    fn retire_idle_relay_connections(&mut self) {
        let now = tokio::time::Instant::now();
        let finished =
            self.relay_retirement
                .iter()
                .filter_map(|(connection_id, (peer, deadline))| {
                    let still_punched = self.connection_paths.values().any(|(candidate, path)| {
                        candidate == peer && *path == P2pPath::HolePunched
                    });
                    if !still_punched {
                        return Some((*connection_id, *peer, false));
                    }
                    let busy = self
                        .pending_requests
                        .values()
                        .any(|pending| pending.peer == *peer)
                        || self
                            .active_inbound_requests
                            .values()
                            .any(|candidate| *candidate == *peer);
                    (*deadline <= now && !busy).then_some((*connection_id, *peer, true))
                })
                .collect::<Vec<_>>();
        for (connection_id, peer, should_close) in finished {
            self.relay_retirement.remove(&connection_id);
            if should_close && self.swarm.close_connection(connection_id) {
                tracing::debug!(
                    %peer,
                    ?connection_id,
                    "retiring idle relay connection after successful DCUtR"
                );
            }
        }
    }

    fn handle_dht_result(&mut self, id: kad::QueryId, result: kad::QueryResult, last: bool) {
        let Some(pending) = self.pending_dht.remove(&id) else {
            return;
        };
        match (pending, result) {
            (PendingDht::Put(response), kad::QueryResult::PutRecord(result)) => {
                let _ = response.send(result.map(|_| ()).map_err(anyhow::Error::new));
            }
            (PendingDht::Provide(response), kad::QueryResult::StartProviding(result)) => {
                let _ = response.send(result.map(|_| ()).map_err(anyhow::Error::new));
            }
            (
                PendingDht::Get {
                    mut records,
                    response,
                },
                kad::QueryResult::GetRecord(result),
            ) => match result {
                Ok(kad::GetRecordOk::FoundRecord(found)) => {
                    if records.len() < MAX_DHT_RECORDS_PER_QUERY {
                        records.push(DhtRecord {
                            publisher: found.record.publisher.map(|peer| peer.to_string()),
                            value: found.record.value,
                        });
                    }
                    if last || records.len() == MAX_DHT_RECORDS_PER_QUERY {
                        let _ = response.send(Ok(records));
                    } else {
                        self.pending_dht
                            .insert(id, PendingDht::Get { records, response });
                    }
                }
                Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                    let _ = response.send(Ok(records));
                }
                Err(kad::GetRecordError::NotFound { .. }) => {
                    let _ = response.send(Ok(records));
                }
                Err(error) => {
                    let _ = response.send(Err(error.into()));
                }
            },
            (
                PendingDht::Providers {
                    mut providers,
                    response,
                },
                kad::QueryResult::GetProviders(result),
            ) => match result {
                Ok(kad::GetProvidersOk::FoundProviders {
                    providers: found, ..
                }) => {
                    for provider in found {
                        if providers.len() == MAX_DHT_PROVIDERS_PER_QUERY {
                            break;
                        }
                        providers.insert(provider.to_string());
                    }
                    if last || providers.len() == MAX_DHT_PROVIDERS_PER_QUERY {
                        let _ = response.send(Ok(providers.into_iter().collect()));
                    } else {
                        self.pending_dht.insert(
                            id,
                            PendingDht::Providers {
                                providers,
                                response,
                            },
                        );
                    }
                }
                Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                    let _ = response.send(Ok(providers.into_iter().collect()));
                }
                Err(error) => {
                    let _ = response.send(Err(error.into()));
                }
            },
            (pending, _) => {
                fail_dht_pending(pending, "Kademlia returned a mismatched query result");
            }
        }
    }
}

pub async fn run_coordinator_jobs(node: Arc<Mutex<Node>>, p2p: P2pClient) -> Result<()> {
    loop {
        let job = node_blocking(node.clone(), |node| node.claim_backup_job()).await?;
        let Some(job) = job else {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        };
        match commit_backup_job(node.clone(), &p2p, &job).await {
            Ok(checkpoint_hash) => {
                let descriptor = job.descriptor.clone();
                node_blocking(node.clone(), move |node| {
                    node.complete_backup_job(&descriptor, checkpoint_hash)
                })
                .await?;
            }
            Err(error) => {
                let descriptor = job.descriptor.clone();
                let message = format!("{error:#}");
                if message.contains("parity storage budget is exhausted") {
                    tracing::warn!(
                        revision = %job.descriptor.revision_id,
                        %error,
                        "coordinator backup failed because a parity host is full"
                    );
                    node_blocking(node.clone(), move |node| {
                        node.fail_backup_job(&descriptor, &message)
                    })
                    .await?;
                } else {
                    tracing::warn!(
                        revision = %job.descriptor.revision_id,
                        %error,
                        "coordinator backup attempt deferred"
                    );
                    node_blocking(node.clone(), move |node| {
                        node.defer_backup_job(&descriptor, &message)
                    })
                    .await?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

pub async fn run_dht_publications(node: Arc<Mutex<Node>>, p2p: P2pClient) -> Result<()> {
    loop {
        if let Err(error) = publish_dht_once(node.clone(), &p2p).await {
            tracing::warn!(%error, "DHT publication/readiness pass failed");
        }
        if let Err(error) = refresh_guild_endpoints(node.clone(), &p2p).await {
            tracing::warn!(%error, "DHT endpoint refresh pass failed");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn refresh_guild_endpoints(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let (guild, local_id) = node_blocking(node, |node| {
        Ok((node.guild_summary()?, node.keys().node_id()))
    })
    .await?;
    let Some(guild) = guild else {
        p2p.set_relay_members(BTreeSet::new()).await?;
        return Ok(());
    };
    if !matches!(guild.phase, GuildPhase::Active) {
        p2p.set_relay_members(BTreeSet::new()).await?;
        return Ok(());
    }
    let relay_members = guild
        .peers
        .iter()
        .filter_map(|peer| peer.member.node_id.libp2p_peer_id().ok())
        .collect();
    p2p.set_relay_members(relay_members).await?;
    let mut queries = FuturesUnordered::new();
    for peer in guild.peers {
        if peer.member.node_id == local_id {
            continue;
        }
        let member = peer.member.node_id;
        let peer_id = member.libp2p_peer_id()?.to_string();
        queries.push(async move { (member, p2p.get_record(endpoint_record_key(&peer_id)).await) });
    }
    while let Some((member, records)) = queries.next().await {
        let records = match records {
            Ok(records) => records,
            Err(error) => {
                tracing::debug!(%member, %error, "guild endpoint lookup failed");
                continue;
            }
        };
        let endpoint = match select_endpoint_record(member, records) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => {
                p2p.replace_learned_peer_addresses(member, Vec::new(), 0)
                    .await?;
                continue;
            }
            Err(error) => {
                tracing::warn!(%member, %error, "guild member published conflicting endpoints");
                continue;
            }
        };
        let expires_at_unix_seconds = endpoint.value.expires_at_unix_seconds;
        let mut addresses = Vec::with_capacity(endpoint.value.endpoints.len());
        for value in endpoint.value.endpoints {
            let Ok(address) = value.parse::<Multiaddr>() else {
                tracing::warn!(%member, endpoint = %value, "ignored malformed signed endpoint");
                continue;
            };
            if address.iter().last()
                != Some(libp2p::multiaddr::Protocol::P2p(member.libp2p_peer_id()?))
            {
                tracing::warn!(%member, endpoint = %value, "ignored endpoint bound to another peer");
                continue;
            }
            addresses.push(address);
        }
        if let Err(error) = p2p
            .replace_learned_peer_addresses(member, addresses, expires_at_unix_seconds)
            .await
        {
            tracing::debug!(%member, %error, "could not replace signed endpoints");
        }
    }
    Ok(())
}

async fn publish_dht_once(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let endpoints = advertised_p2p_endpoints(p2p).await?;
    let expires = unix_seconds()
        .checked_add(DHT_TTL.as_secs())
        .context("DHT publication expiry overflow")?;
    let (local_id, probe_subjects) = node_blocking(node.clone(), |node| {
        Ok((
            node.keys().node_id(),
            node.dht_recovery_sequence_probe_subjects()?,
        ))
    })
    .await?;
    let local_peer = p2p.local_peer_id();
    let mut sequence_floors = DhtSequenceFloors::default();
    if !probe_subjects.is_empty() {
        let records = p2p.get_record(endpoint_record_key(&local_peer)).await?;
        sequence_floors.endpoint =
            next_sequence_floor(highest_endpoint_sequence(local_id, records)?)?;
        let mut queries = FuturesUnordered::new();
        for subject in probe_subjects {
            let publisher = local_peer.clone();
            let key = recovery_bundle_key(subject, &local_peer);
            queries.push(async move { (publisher, subject, p2p.get_record(key).await) });
        }
        while let Some((publisher, subject, records)) = queries.next().await {
            sequence_floors.recovery.insert(
                subject,
                next_sequence_floor(highest_recovery_sequence(&publisher, subject, records?)?)?,
            );
        }
    }
    let Some(publications) = node_blocking(node.clone(), move |node| {
        node.build_dht_publications(endpoints, expires, sequence_floors)
    })
    .await?
    else {
        return Ok(());
    };
    p2p.put_record(
        endpoint_record_key(&local_peer),
        canonical_bytes(&publications.endpoint)?,
    )
    .await?;
    for bundle in publications.recovery {
        let subject = bundle.value.subject;
        p2p.put_record(
            recovery_bundle_key(subject, &local_peer),
            canonical_bytes(&bundle)?,
        )
        .await?;
        p2p.start_providing(recovery_mailbox_key(subject)).await?;
    }

    let providers = p2p.get_providers(recovery_mailbox_key(local_id)).await?;
    let mut bundle_queries = FuturesUnordered::new();
    for provider in providers {
        if provider == local_peer {
            continue;
        }
        let key = recovery_bundle_key(local_id, &provider);
        bundle_queries.push(async move { (provider, p2p.get_record(key).await) });
    }
    let mut confirmations = Vec::new();
    while let Some((provider, records)) = bundle_queries.next().await {
        let Ok(records) = records else {
            tracing::warn!(%provider, "DHT readiness provider lookup failed");
            continue;
        };
        let bundle = match select_recovery_bundle(&provider, local_id, records) {
            Ok(Some(bundle)) => bundle,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%provider, %error, "rejected conflicting DHT readiness records");
                continue;
            }
        };
        let publisher = bundle.value.publisher;
        let expires_at = bundle.value.expires_at_unix_seconds;
        if validate_ready_bundle(
            node.clone(),
            &provider,
            publications.checkpoint_hash,
            bundle,
        )
        .await
        .is_ok()
        {
            confirmations.push((publisher, expires_at));
        }
    }
    let hash = publications.checkpoint_hash;
    node_blocking(node, move |node| {
        node.update_seed_recovery_readiness(hash, confirmations)
    })
    .await?;
    Ok(())
}

async fn validate_ready_bundle(
    node: Arc<Mutex<Node>>,
    provider_peer_id: &str,
    checkpoint_hash: [u8; 32],
    bundle: SignedRecord<mb_core::RecoveryBundle>,
) -> Result<()> {
    let provider_peer_id = provider_peer_id.to_owned();
    node_blocking(node, move |node| {
        bundle.verify(b"mutualbackup/recovery-bundle/v1")?;
        if bundle.value.format_version != 1
            || bundle.value.subject != node.keys().node_id()
            || bundle.value.publisher != bundle.signer
            || bundle.value.sequence == 0
            || bundle.value.expires_at_unix_seconds <= unix_seconds()
            || bundle.value.publisher.libp2p_peer_id()?.to_string() != provider_peer_id
        {
            bail!("invalid DHT recovery bundle");
        }
        let plaintext = open_recovery_record(node.keys(), &bundle.value.sealed)?;
        let locator: SignedRecord<mb_core::RecoveryLocator> = decode_canonical(&plaintext)?;
        locator.verify(RECOVERY_LOCATOR_DOMAIN)?;
        if locator.signer != bundle.value.publisher
            || locator.value.publisher != bundle.value.publisher
            || locator.value.subject != bundle.value.subject
            || locator.value.checkpoint_hash != checkpoint_hash
            || locator.value.expires_at_unix_seconds != bundle.value.expires_at_unix_seconds
            || !valid_endpoint_values(locator.value.publisher, &locator.value.endpoints)
        {
            bail!("sealed recovery locator differs from its DHT bundle");
        }
        let checkpoint = node.checkpoint(&checkpoint_hash)?;
        checkpoint.validate_recovery_authority(
            node.keys(),
            &locator.value,
            bundle.value.publisher,
        )?;
        Ok(())
    })
    .await
}

pub fn recovery_mailbox_key(subject: NodeId) -> Vec<u8> {
    dht_key(b"mailbox", &[&subject.0])
}

pub fn recovery_bundle_key(subject: NodeId, publisher_peer_id: &str) -> Vec<u8> {
    dht_key(
        b"recovery-bundle",
        &[&subject.0, publisher_peer_id.as_bytes()],
    )
}

pub fn endpoint_record_key(publisher_peer_id: &str) -> Vec<u8> {
    dht_key(b"endpoint", &[publisher_peer_id.as_bytes()])
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DhtRecoveryResult {
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub generation: u64,
    pub revision_id: Option<Uuid>,
}

#[derive(Clone)]
struct RecoveryCandidate {
    publisher: NodeId,
    locator: mb_core::RecoveryLocator,
}

struct ValidatedRecoveryHead {
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    generation: u64,
    genesis: QuorumGuildGenesis,
    checkpoint: QuorumCheckpoint,
    candidates: Vec<RecoveryCandidate>,
}

pub async fn recover_from_dht(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    restore_target: &std::path::Path,
) -> Result<DhtRecoveryResult> {
    let subject = node_blocking(node.clone(), |node| Ok(node.keys().node_id())).await?;
    let providers = p2p.get_providers(recovery_mailbox_key(subject)).await?;
    let mut bundle_queries = FuturesUnordered::new();
    for provider in providers {
        let key = recovery_bundle_key(subject, &provider);
        bundle_queries.push(async move { (provider, p2p.get_record(key).await) });
    }
    let mut candidates = Vec::new();
    while let Some((provider, records)) = bundle_queries.next().await {
        let Ok(records) = records else {
            tracing::warn!(%provider, "recovery provider lookup failed");
            continue;
        };
        let bundle = match select_recovery_bundle(&provider, subject, records) {
            Ok(Some(bundle)) => bundle,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%provider, %error, "recovery provider published conflicting records");
                continue;
            }
        };
        let provider_for_check = provider.clone();
        match node_blocking(node.clone(), move |node| {
            decode_recovery_candidate(node, &provider_for_check, bundle)
        })
        .await
        {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => {
                tracing::warn!(%provider, %error, "ignored invalid recovery candidate");
            }
        }
    }
    let mut candidates_by_head = BTreeMap::<_, Vec<RecoveryCandidate>>::new();
    for candidate in candidates {
        candidates_by_head
            .entry((
                candidate.locator.checkpoint_generation,
                candidate.locator.guild_id,
                candidate.locator.checkpoint_hash,
            ))
            .or_default()
            .push(candidate);
    }
    for group in candidates_by_head.values_mut() {
        group.sort_by_key(|candidate| candidate.publisher);
        group.dedup_by_key(|candidate| candidate.publisher);
    }
    let mut generations = candidates_by_head
        .iter()
        .filter(|(_, candidates)| candidates.len() >= 3)
        .map(|((generation, _, _), _)| *generation)
        .collect::<Vec<_>>();
    generations.sort_unstable_by(|left, right| right.cmp(left));
    generations.dedup();
    if generations.is_empty() {
        bail!("Kademlia returned no recovery head confirmed by three publishers");
    }

    let mut selected = None;
    for generation in generations {
        let mut valid_heads = Vec::new();
        for ((head_generation, guild_id, checkpoint_hash), head_candidates) in &candidates_by_head {
            if *head_generation != generation {
                continue;
            }
            match validate_recovery_head(
                node.clone(),
                p2p,
                *guild_id,
                *checkpoint_hash,
                generation,
                head_candidates.clone(),
            )
            .await
            {
                Ok(head) => valid_heads.push(head),
                Err(error) => {
                    tracing::warn!(generation, %error, "ignored uncertified recovery head");
                }
            }
        }
        match valid_heads.len() {
            0 => continue,
            1 => {
                selected = valid_heads.pop();
                break;
            }
            _ => bail!("multiple certified recovery heads exist at generation {generation}"),
        }
    }
    let ValidatedRecoveryHead {
        guild_id,
        checkpoint_hash,
        generation,
        genesis,
        checkpoint,
        candidates,
    } = selected.context("no advertised recovery head could be certified")?;

    let local_endpoints = advertised_p2p_endpoints(p2p).await?;
    let mut roster = genesis
        .genesis
        .members
        .iter()
        .cloned()
        .map(|member| GuildPeer {
            member,
            endpoints: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut endpoint_queries = FuturesUnordered::new();
    for peer in &roster {
        if peer.member.node_id == subject {
            continue;
        }
        let member = peer.member.node_id;
        let peer_id = member.libp2p_peer_id()?.to_string();
        endpoint_queries
            .push(async move { (member, p2p.get_record(endpoint_record_key(&peer_id)).await) });
    }
    let mut endpoint_records = HashMap::new();
    while let Some((member, records)) = endpoint_queries.next().await {
        match records {
            Ok(records) => {
                endpoint_records.insert(member, records);
            }
            Err(error) => {
                tracing::warn!(%member, %error, "endpoint lookup failed during recovery");
            }
        }
    }
    for peer in &mut roster {
        if peer.member.node_id == subject {
            peer.endpoints = local_endpoints.clone();
            continue;
        }
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.publisher == peer.member.node_id)
        {
            peer.endpoints = candidate.locator.endpoints.clone();
        }
        match select_endpoint_record(
            peer.member.node_id,
            endpoint_records
                .remove(&peer.member.node_id)
                .unwrap_or_default(),
        ) {
            Ok(Some(endpoint)) => peer.endpoints = endpoint.value.endpoints,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(member = %peer.member.node_id, %error, "ignored conflicting endpoint records");
            }
        }
        let mut usable_endpoints = Vec::new();
        for endpoint in &peer.endpoints {
            let Ok(address) = endpoint.parse::<Multiaddr>() else {
                tracing::warn!(member = %peer.member.node_id, %endpoint, "ignored malformed endpoint");
                continue;
            };
            match p2p.add_peer_address(peer.member.node_id, address).await {
                Ok(()) => usable_endpoints.push(endpoint.clone()),
                Err(error) => {
                    tracing::warn!(member = %peer.member.node_id, %endpoint, %error, "ignored unusable endpoint");
                }
            }
        }
        peer.endpoints = usable_endpoints;
    }
    let recovered_genesis = genesis.clone();
    let recovered_roster = roster.clone();
    node_blocking(node.clone(), move |node| {
        node.adopt_recovered_guild(recovered_genesis, recovered_roster)
    })
    .await?;
    recover_p2p_local_shards(node.clone(), p2p, &checkpoint, &roster).await?;
    let recovered_checkpoint = checkpoint.clone();
    node_blocking(node.clone(), move |node| {
        node.install_recovered_checkpoint(&recovered_checkpoint)?;
        Ok(())
    })
    .await?;
    let revision = checkpoint
        .checkpoint
        .revisions
        .iter()
        .filter(|revision| revision.value.owner == subject)
        .max_by_key(|revision| revision.value.sequence)
        .cloned();
    let revision_id = revision.as_ref().map(|revision| revision.value.revision_id);
    if let Some(revision) = revision {
        if restore_target.exists() {
            bail!("restore target must not already exist");
        }
        let target = restore_target.to_path_buf();
        node_blocking(node, move |node| {
            node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
        })
        .await?;
    }
    Ok(DhtRecoveryResult {
        guild_id,
        checkpoint_hash,
        generation,
        revision_id,
    })
}

async fn validate_recovery_head(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    generation: u64,
    candidates: Vec<RecoveryCandidate>,
) -> Result<ValidatedRecoveryHead> {
    for candidate in &candidates {
        for endpoint in &candidate.locator.endpoints {
            let Ok(address) = endpoint.parse::<Multiaddr>() else {
                continue;
            };
            if let Err(error) = p2p.add_peer_address(candidate.publisher, address).await {
                tracing::debug!(publisher = %candidate.publisher, %endpoint, %error, "candidate endpoint was not usable");
            }
        }
    }
    let mut state_attempts = FuturesUnordered::new();
    for candidate in &candidates {
        let publisher = candidate.publisher;
        state_attempts.push(async move {
            let genesis = p2p.guild_genesis(publisher, guild_id).await?;
            let checkpoint =
                fetch_p2p_checkpoint(p2p, publisher, guild_id, checkpoint_hash).await?;
            Ok::<_, anyhow::Error>((genesis, checkpoint))
        });
    }
    while let Some(attempt) = state_attempts.next().await {
        let Ok((genesis, checkpoint)) = attempt else {
            continue;
        };
        let state_matches = (|| -> Result<bool> {
            genesis.verify()?;
            checkpoint.verify()?;
            Ok(genesis.genesis.guild_id == guild_id
                && genesis.hash()? == checkpoint.checkpoint.genesis_hash
                && checkpoint.checkpoint.guild_id == guild_id
                && checkpoint.checkpoint.generation == generation
                && checkpoint.hash()? == checkpoint_hash
                && checkpoint.checkpoint.members == genesis.genesis.members)
        })()
        .unwrap_or(false);
        if !state_matches {
            continue;
        }
        let checkpoint_for_validation = checkpoint.clone();
        let candidates_for_validation = candidates.clone();
        let valid_candidates = node_blocking(node.clone(), move |node| {
            Ok(candidates_for_validation
                .iter()
                .filter(|candidate| {
                    checkpoint_for_validation
                        .validate_recovery_authority(
                            node.keys(),
                            &candidate.locator,
                            candidate.publisher,
                        )
                        .is_ok()
                })
                .cloned()
                .collect::<Vec<_>>())
        })
        .await?;
        if valid_candidates.len() >= 3 {
            return Ok(ValidatedRecoveryHead {
                guild_id,
                checkpoint_hash,
                generation,
                genesis,
                checkpoint,
                candidates: valid_candidates,
            });
        }
    }
    bail!("no publisher served a certified state authorizing three recovery locators")
}

fn decode_recovery_candidate(
    node: &Node,
    provider_peer_id: &str,
    bundle: SignedRecord<mb_core::RecoveryBundle>,
) -> Result<RecoveryCandidate> {
    bundle.verify(b"mutualbackup/recovery-bundle/v1")?;
    if bundle.value.format_version != 1
        || bundle.value.subject != node.keys().node_id()
        || bundle.value.publisher != bundle.signer
        || bundle.value.sequence == 0
        || bundle.value.expires_at_unix_seconds <= unix_seconds()
        || bundle.value.publisher.libp2p_peer_id()?.to_string() != provider_peer_id
    {
        bail!("invalid recovery bundle context");
    }
    let plaintext = open_recovery_record(node.keys(), &bundle.value.sealed)?;
    let locator: SignedRecord<mb_core::RecoveryLocator> = decode_canonical(&plaintext)?;
    locator.verify(RECOVERY_LOCATOR_DOMAIN)?;
    if locator.signer != bundle.value.publisher
        || locator.value.format_version != 1
        || locator.value.subject != bundle.value.subject
        || locator.value.publisher != bundle.value.publisher
        || locator.value.expires_at_unix_seconds != bundle.value.expires_at_unix_seconds
        || locator.value.expires_at_unix_seconds <= unix_seconds()
        || !valid_endpoint_values(locator.value.publisher, &locator.value.endpoints)
    {
        bail!("sealed recovery locator differs from its bundle");
    }
    Ok(RecoveryCandidate {
        publisher: bundle.value.publisher,
        locator: locator.value,
    })
}

fn select_recovery_bundle(
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<SignedRecord<mb_core::RecoveryBundle>>> {
    let mut selected: Option<(u64, [u8; 32], SignedRecord<mb_core::RecoveryBundle>)> = None;
    for record in records {
        let Ok(bundle) = decode_canonical::<SignedRecord<mb_core::RecoveryBundle>>(&record.value)
        else {
            continue;
        };
        if bundle.verify(b"mutualbackup/recovery-bundle/v1").is_err()
            || bundle.value.format_version != 1
            || bundle.value.subject != subject
            || bundle.value.publisher != bundle.signer
            || bundle.value.sequence == 0
            || bundle.value.expires_at_unix_seconds <= unix_seconds()
            || bundle.value.publisher.libp2p_peer_id()?.to_string() != provider_peer_id
        {
            continue;
        }
        let hash = *blake3::hash(&canonical_bytes(&bundle)?).as_bytes();
        match &selected {
            Some((sequence, existing_hash, _)) if *sequence == bundle.value.sequence => {
                if *existing_hash != hash {
                    bail!("recovery publisher forked one DHT sequence");
                }
            }
            Some((sequence, _, _)) if *sequence > bundle.value.sequence => {}
            _ => selected = Some((bundle.value.sequence, hash, bundle)),
        }
    }
    Ok(selected.map(|(_, _, bundle)| bundle))
}

fn select_endpoint_record(
    publisher: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<SignedRecord<mb_core::EndpointRecord>>> {
    let mut selected: Option<(u64, [u8; 32], SignedRecord<mb_core::EndpointRecord>)> = None;
    for record in records {
        let Ok(endpoint) = decode_canonical::<SignedRecord<mb_core::EndpointRecord>>(&record.value)
        else {
            continue;
        };
        if endpoint.verify(b"mutualbackup/endpoint-record/v1").is_err()
            || endpoint.value.format_version != 1
            || endpoint.signer != publisher
            || endpoint.value.publisher != publisher
            || endpoint.value.sequence == 0
            || endpoint.value.expires_at_unix_seconds <= unix_seconds()
            || !valid_endpoint_values(publisher, &endpoint.value.endpoints)
        {
            continue;
        }
        let hash = *blake3::hash(&canonical_bytes(&endpoint)?).as_bytes();
        match &selected {
            Some((sequence, existing_hash, _)) if *sequence == endpoint.value.sequence => {
                if *existing_hash != hash {
                    bail!("endpoint publisher forked one DHT sequence");
                }
            }
            Some((sequence, _, _)) if *sequence > endpoint.value.sequence => {}
            _ => selected = Some((endpoint.value.sequence, hash, endpoint)),
        }
    }
    Ok(selected.map(|(_, _, endpoint)| endpoint))
}

fn valid_endpoint_values(publisher: NodeId, endpoints: &[String]) -> bool {
    if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS_PER_PEER {
        return false;
    }
    let Ok(expected) = publisher.libp2p_peer_id() else {
        return false;
    };
    let mut unique = BTreeSet::new();
    endpoints.iter().all(|value| {
        value.len() <= 512
            && unique.insert(value)
            && value.parse::<Multiaddr>().is_ok_and(|address| {
                address.iter().last() == Some(libp2p::multiaddr::Protocol::P2p(expected))
            })
    })
}

fn highest_endpoint_sequence(publisher: NodeId, records: Vec<DhtRecord>) -> Result<Option<u64>> {
    let mut highest = None;
    for record in records {
        let Ok(endpoint) = decode_canonical::<SignedRecord<mb_core::EndpointRecord>>(&record.value)
        else {
            continue;
        };
        if endpoint.verify(b"mutualbackup/endpoint-record/v1").is_ok()
            && endpoint.signer == publisher
            && endpoint.value.publisher == publisher
            && endpoint.value.sequence > 0
        {
            highest = Some(highest.unwrap_or(0).max(endpoint.value.sequence));
        }
    }
    Ok(highest)
}

fn highest_recovery_sequence(
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<u64>> {
    let mut highest = None;
    for record in records {
        let Ok(bundle) = decode_canonical::<SignedRecord<mb_core::RecoveryBundle>>(&record.value)
        else {
            continue;
        };
        if bundle.verify(b"mutualbackup/recovery-bundle/v1").is_ok()
            && bundle.value.format_version == 1
            && bundle.value.subject == subject
            && bundle.value.publisher == bundle.signer
            && bundle.value.sequence > 0
            && bundle.value.publisher.libp2p_peer_id()?.to_string() == provider_peer_id
        {
            highest = Some(highest.unwrap_or(0).max(bundle.value.sequence));
        }
    }
    Ok(highest)
}

fn next_sequence_floor(highest: Option<u64>) -> Result<u64> {
    highest
        .unwrap_or(0)
        .checked_add(1)
        .context("DHT publication sequence is exhausted")
}

async fn fetch_p2p_checkpoint(
    p2p: &P2pClient,
    publisher: NodeId,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
) -> Result<QuorumCheckpoint> {
    let (total_pages, first_hash, first) = p2p
        .checkpoint_page(publisher, guild_id, checkpoint_hash, 0)
        .await?;
    if total_pages == 0
        || total_pages > V1_MAX_CATALOG_PAGES
        || first.is_empty()
        || first.len() > V1_CATALOG_PAGE_BYTES
        || first_hash != *blake3::hash(&first).as_bytes()
    {
        bail!("checkpoint first page failed validation");
    }
    let mut bytes = first;
    for page_index in 1..total_pages {
        let (actual_total, page_hash, page) = p2p
            .checkpoint_page(publisher, guild_id, checkpoint_hash, page_index)
            .await?;
        if actual_total != total_pages
            || page.is_empty()
            || page.len() > V1_CATALOG_PAGE_BYTES
            || page_hash != *blake3::hash(&page).as_bytes()
            || bytes.len().saturating_add(page.len()) > V1_MAX_CATALOG_BYTES
        {
            bail!("checkpoint page failed validation");
        }
        bytes.extend_from_slice(&page);
    }
    let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
    checkpoint.verify()?;
    if checkpoint.hash()? != checkpoint_hash {
        bail!("assembled checkpoint has the wrong hash");
    }
    Ok(checkpoint)
}

async fn recover_p2p_local_shards(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    checkpoint: &QuorumCheckpoint,
    roster: &[GuildPeer],
) -> Result<()> {
    let recovering = node_blocking(node.clone(), |node| Ok(node.keys().node_id())).await?;
    let checkpoint_hash = checkpoint.hash()?;
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
        let bytes = reconstruct_shard_from_peers(p2p, group, target_index, roster).await?;
        if sector_root(&bytes) != target_root {
            bail!("reconstructed target shard failed its certified root");
        }
        let group = group.clone();
        let guild_id = checkpoint.checkpoint.guild_id;
        node_blocking(node.clone(), move |node| {
            node.stage_recovered_shard(
                &checkpoint_hash,
                &guild_id,
                &group,
                target_index as u8,
                &bytes,
            )
        })
        .await?;
    }
    Ok(())
}

async fn reconstruct_shard_from_peers(
    p2p: &P2pClient,
    group: &CodingGroup,
    target_index: usize,
    roster: &[GuildPeer],
) -> Result<Vec<u8>> {
    if target_index >= group.roles.len() {
        bail!("target shard index is outside its coding group");
    }
    for peer in roster {
        for endpoint in &peer.endpoints {
            let Ok(address) = endpoint.parse::<Multiaddr>() else {
                continue;
            };
            let _ = p2p.add_peer_address(peer.member.node_id, address).await;
        }
    }
    let mut shards = vec![None; group.roles.len()];
    for attempt in 0..SHARD_FETCH_ATTEMPTS {
        let mut requests = FuturesUnordered::new();
        for (index, role) in group.roles.iter().enumerate() {
            if index == target_index || shards[index].is_some() {
                continue;
            }
            let (holder, root, sector_id) = match role {
                ShardRole::Information(information) => (
                    information.owner,
                    information.sector.root,
                    Some(information.sector.id),
                ),
                ShardRole::Parity(parity) => (parity.holder, parity.root, None),
            };
            if !roster.iter().any(|peer| peer.member.node_id == holder) {
                continue;
            }
            let client = p2p.clone();
            let guild_id = group.guild_id;
            let group_id = group.id;
            requests.push(async move {
                let result = if let Some(sector_id) = sector_id {
                    client.sector(holder, guild_id, sector_id).await
                } else {
                    client.parity(holder, guild_id, group_id, index as u8).await
                };
                (index, root, result)
            });
        }
        while let Some((index, root, result)) = requests.next().await {
            if let Ok(bytes) = result
                && bytes.len() == group.shard_size as usize
                && sector_root(&bytes) == root
            {
                shards[index] = Some(bytes);
            }
            // Reconstruction needs any three valid shards. Do not wait for an
            // unrelated offline holder once that threshold has been reached;
            // cold recovery can span many coding groups and otherwise pays the
            // full request timeout once per group.
            if shards.iter().filter(|shard| shard.is_some()).count()
                >= usize::from(V1_RS_DATA_SHARDS)
            {
                break;
            }
        }
        if shards.iter().filter(|shard| shard.is_some()).count() >= usize::from(V1_RS_DATA_SHARDS) {
            break;
        }
        if attempt + 1 < SHARD_FETCH_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    if shards.iter().filter(|shard| shard.is_some()).count() < usize::from(V1_RS_DATA_SHARDS) {
        bail!(
            "coding group {} has fewer than three reachable valid shards after {} attempts",
            hex::encode(group.id),
            SHARD_FETCH_ATTEMPTS
        );
    }
    mb_core::reconstruct_3_2(&mut shards)?;
    shards[target_index]
        .take()
        .context("target shard was not reconstructed")
}

pub(crate) async fn restore_snapshot_with_p2p(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    revision_id: Option<Uuid>,
    target: &std::path::Path,
) -> Result<SnapshotInfo> {
    if target.exists() {
        bail!("restore target must not already exist");
    }
    let (checkpoint, revision, roster) = node_blocking(node.clone(), move |node| {
        node.snapshot_repair_plan(revision_id)
    })
    .await?;
    let guild_id = checkpoint.checkpoint.guild_id;
    let references = revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .cloned()
        .collect::<Vec<_>>();
    for reference in references {
        let sector_id = reference.id;
        let expected_root = reference.root;
        let local_is_valid = node_blocking(node.clone(), move |node| {
            Ok(node
                .sector_for_guild(&guild_id, &sector_id)
                .is_ok_and(|bytes| {
                    bytes.len() == V1_SECTOR_SIZE && sector_root(&bytes) == expected_root
                }))
        })
        .await?;
        if local_is_valid {
            continue;
        }
        let (group, target_index) = checkpoint
            .checkpoint
            .coding_groups
            .iter()
            .find_map(|group| {
                group
                    .roles
                    .iter()
                    .enumerate()
                    .find(|(_, role)| {
                        matches!(role, ShardRole::Information(information) if information.sector == reference)
                    })
                    .map(|(index, _)| (group, index))
            })
            .context("snapshot sector is not present in the certified coding catalog")?;
        let bytes = reconstruct_shard_from_peers(p2p, group, target_index, &roster).await?;
        let reference_for_install = reference.clone();
        node_blocking(node.clone(), move |node| {
            node.install_repaired_information_sector(guild_id, reference_for_install, &bytes)
        })
        .await?;
    }
    let target = target.to_path_buf();
    let selected_revision = revision.value.revision_id;
    node_blocking(node, move |node| {
        node.restore_snapshot(Some(selected_revision), &target)
    })
    .await
}

fn dht_key(kind: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup kademlia key v1");
    hasher.update(kind);
    for part in parts {
        hasher.update(&((*part).len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().as_bytes().to_vec()
}

async fn advertised_p2p_endpoints(p2p: &P2pClient) -> Result<Vec<String>> {
    let status = p2p.status().await?;
    let peer_id: PeerId = status.peer_id.parse()?;
    let mut endpoints = Vec::new();
    for value in status.advertised_addresses {
        let mut address: Multiaddr = value.parse()?;
        if address.iter().any(|protocol| match protocol {
            libp2p::multiaddr::Protocol::Ip4(address) => address.is_unspecified(),
            libp2p::multiaddr::Protocol::Ip6(address) => address.is_unspecified(),
            _ => false,
        }) {
            continue;
        }
        match address.iter().last() {
            Some(libp2p::multiaddr::Protocol::P2p(actual)) if actual == peer_id => {}
            Some(libp2p::multiaddr::Protocol::P2p(_)) => {
                bail!("advertised endpoint contains another peer identity")
            }
            _ => address.push(libp2p::multiaddr::Protocol::P2p(peer_id)),
        }
        endpoints.push(address.to_string());
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        bail!("daemon has no usable DHT endpoint");
    }
    Ok(endpoints)
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn commit_backup_job(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    job: &BackupJob,
) -> Result<[u8; 32]> {
    let guild_id = job.descriptor.guild_id;
    let (certificate, mut peers, local_id, previous) = node_blocking(node.clone(), move |node| {
        let certificate = node
            .installed_guild_certificate()?
            .context("coordinator has no installed guild genesis")?;
        let summary = node
            .guild_summary()?
            .context("coordinator has no guild endpoint roster")?;
        let previous = node.current_checkpoint(guild_id)?;
        Ok((certificate, summary.peers, node.keys().node_id(), previous))
    })
    .await?;
    certificate.verify()?;
    if certificate.genesis.guild_id != guild_id
        || certificate.genesis.coordinator != local_id
        || job.descriptor.owner == local_id
            && !peers.iter().any(|peer| peer.member.node_id == local_id)
    {
        bail!("backup job does not belong to this certified coordinator");
    }
    if let Some(checkpoint) = &previous
        && checkpoint.checkpoint.revisions.iter().any(|revision| {
            revision.value.revision_id == job.descriptor.revision_id
                && revision.value.owner == job.descriptor.owner
        })
    {
        return checkpoint.hash().map_err(Into::into);
    }
    let owner_position = peers
        .iter()
        .position(|peer| peer.member.node_id == job.descriptor.owner)
        .context("backup owner is not a guild member")?;
    let owner = peers.remove(owner_position);
    peers.sort_by_key(|peer| peer.member.node_id);
    peers.insert(0, owner);
    if peers.len() != 5 {
        bail!("prototype backup requires exactly five guild peers");
    }
    for peer in peers.iter().filter(|peer| peer.member.node_id != local_id) {
        for endpoint in &peer.endpoints {
            p2p.add_peer_address(peer.member.node_id, endpoint.parse()?)
                .await?;
        }
    }

    let revision = fetch_p2p_revision(node.clone(), p2p, local_id, &job.descriptor).await?;
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.signer != job.descriptor.owner
        || revision.value.owner != job.descriptor.owner
        || revision.value.guild_id != guild_id
        || revision.value.revision_id != job.descriptor.revision_id
    {
        bail!("prepared revision does not match its backup submission");
    }
    let mut target_sectors = revision.value.metadata_sectors.clone();
    target_sectors.extend(revision.value.data_sectors.clone());
    if target_sectors.is_empty() || target_sectors.len() > V1_MAX_CODING_GROUPS {
        bail!("prepared revision exceeds the bounded coding catalog");
    }

    let mut new_groups = Vec::with_capacity(target_sectors.len());
    for (ordinal, target) in target_sectors.iter().enumerate() {
        let owner_bytes = load_p2p_sector(
            node.clone(),
            p2p,
            local_id,
            peers[0].member.node_id,
            guild_id,
            target.id,
        )
        .await?;
        if owner_bytes.len() != V1_SECTOR_SIZE || sector_root(&owner_bytes) != target.root {
            bail!("owner sector failed its committed root or fixed size");
        }
        let helper_a = ensure_p2p_filler(
            node.clone(),
            p2p,
            local_id,
            peers[1].member.node_id,
            guild_id,
            revision.value.revision_id,
            ordinal as u64 * 2,
        )
        .await?;
        let helper_b = ensure_p2p_filler(
            node.clone(),
            p2p,
            local_id,
            peers[2].member.node_id,
            guild_id,
            revision.value.revision_id,
            ordinal as u64 * 2 + 1,
        )
        .await?;
        let shards = encode_3_2([owner_bytes, helper_a.1, helper_b.1])?;
        let roles = [
            ShardRole::Information(InformationRole {
                owner: peers[0].member.node_id,
                sector: target.clone(),
            }),
            ShardRole::Information(InformationRole {
                owner: peers[1].member.node_id,
                sector: helper_a.0,
            }),
            ShardRole::Information(InformationRole {
                owner: peers[2].member.node_id,
                sector: helper_b.0,
            }),
            ShardRole::Parity(ParityRole {
                holder: peers[3].member.node_id,
                row: 0,
                root: sector_root(&shards[3]),
            }),
            ShardRole::Parity(ParityRole {
                holder: peers[4].member.node_id,
                row: 1,
                root: sector_root(&shards[4]),
            }),
        ];
        let mut group = CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id,
            data_shards: V1_RS_DATA_SHARDS,
            parity_shards: V1_RS_PARITY_SHARDS,
            shard_size: V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id()?;
        let information = [shards[0].clone(), shards[1].clone(), shards[2].clone()];
        for (position, shard_index) in [(3_usize, 3_u8), (4, 4)] {
            let object = ParityObject {
                format_version: 1,
                guild_id,
                group_id: group.id,
                shard_index,
                root: sector_root(&shards[position]),
                bytes: shards[position].clone(),
            };
            publish_p2p_parity(
                node.clone(),
                p2p,
                local_id,
                peers[position].member.node_id,
                group.clone(),
                information.clone(),
                object,
            )
            .await?;
        }
        new_groups.push(group);
    }

    let (generation, parent, mut revisions, mut coding_groups) = match previous {
        Some(previous) => {
            previous.verify()?;
            (
                previous
                    .checkpoint
                    .generation
                    .checked_add(1)
                    .context("checkpoint generation exhausted")?,
                Some(previous.hash()?),
                previous.checkpoint.revisions,
                previous.checkpoint.coding_groups,
            )
        }
        None => (1, None, Vec::new(), Vec::new()),
    };
    revisions.push(revision);
    revisions.sort_by_key(|revision| {
        (
            revision.value.owner,
            revision.value.sequence,
            revision.value.revision_id,
        )
    });
    coding_groups.extend(new_groups);
    coding_groups.sort_by_key(|group| group.id);
    let checkpoint = GuildCheckpoint {
        format_version: 1,
        guild_id,
        genesis_hash: certificate.hash()?,
        generation,
        parent,
        members: certificate.genesis.members.clone(),
        revisions,
        coding_groups,
    };
    checkpoint.validate()?;
    let checkpoint_hash = checkpoint.hash()?;
    let body = canonical_bytes(&checkpoint)?;
    publish_p2p_checkpoint_object(
        node.clone(),
        p2p,
        local_id,
        &peers,
        CheckpointObjectKind::Body,
        guild_id,
        checkpoint_hash,
        &body,
    )
    .await?;
    let mut signatures = Vec::with_capacity(5);
    for peer in &peers {
        let signer = peer.member.node_id;
        let signature = if signer == local_id {
            let checkpoint = checkpoint.clone();
            node_blocking(node.clone(), move |node| node.sign_checkpoint(&checkpoint)).await?
        } else {
            p2p.sign_checkpoint(signer, guild_id, checkpoint_hash)
                .await?
        };
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.signer);
    let quorum = QuorumCheckpoint {
        checkpoint,
        signatures,
    };
    quorum.verify()?;
    let certificate_bytes = canonical_bytes(&quorum)?;
    publish_p2p_checkpoint_object(
        node.clone(),
        p2p,
        local_id,
        &peers,
        CheckpointObjectKind::Certificate,
        guild_id,
        checkpoint_hash,
        &certificate_bytes,
    )
    .await?;
    for peer in peers.iter().filter(|peer| peer.member.node_id != local_id) {
        p2p.finalize_checkpoint(peer.member.node_id, guild_id, checkpoint_hash)
            .await?;
    }
    node_blocking(node, move |node| {
        node.finalize_staged_checkpoint(&guild_id, &checkpoint_hash)?;
        Ok(())
    })
    .await?;
    Ok(checkpoint_hash)
}

async fn fetch_p2p_revision(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    descriptor: &BackupDescriptor,
) -> Result<SignedRecord<UserRevision>> {
    if descriptor.owner == local_id {
        let guild_id = descriptor.guild_id;
        let revision_id = descriptor.revision_id;
        let bytes = node_blocking(node, move |node| {
            node.prepared_revision_bytes(guild_id, revision_id)
        })
        .await?;
        if blake3::hash(&bytes).as_bytes() != &descriptor.object_hash {
            bail!("local prepared revision hash differs from its submission");
        }
        return decode_canonical(&bytes).map_err(Into::into);
    }
    let mut bytes = Vec::new();
    for page_index in 0..descriptor.total_pages {
        let (total_pages, page_hash, page) = p2p
            .prepared_revision_page(
                descriptor.owner,
                descriptor.guild_id,
                descriptor.revision_id,
                page_index,
            )
            .await?;
        if total_pages != descriptor.total_pages
            || page_hash != *blake3::hash(&page).as_bytes()
            || page.len() > V1_CATALOG_PAGE_BYTES
            || bytes.len().saturating_add(page.len()) > V1_MAX_CATALOG_BYTES
        {
            bail!("prepared revision page failed bounds or hash validation");
        }
        bytes.extend_from_slice(&page);
    }
    if blake3::hash(&bytes).as_bytes() != &descriptor.object_hash {
        bail!("assembled prepared revision hash differs from its submission");
    }
    decode_canonical(&bytes).map_err(Into::into)
}

async fn load_p2p_sector(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    peer: NodeId,
    guild_id: [u8; 32],
    sector_id: SectorId,
) -> Result<Vec<u8>> {
    if peer == local_id {
        node_blocking(node, move |node| {
            node.sector_for_guild(&guild_id, &sector_id)
        })
        .await
    } else {
        p2p.sector(peer, guild_id, sector_id).await
    }
}

async fn ensure_p2p_filler(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    peer: NodeId,
    guild_id: [u8; 32],
    revision_id: Uuid,
    ordinal: u64,
) -> Result<(SectorRef, Vec<u8>)> {
    if peer == local_id {
        node_blocking(node, move |node| {
            node.ensure_filler(guild_id, revision_id, ordinal)
        })
        .await
    } else {
        p2p.ensure_filler(peer, guild_id, revision_id, ordinal)
            .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_p2p_parity(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    peer: NodeId,
    group: CodingGroup,
    information: [Vec<u8>; 3],
    object: ParityObject,
) -> Result<()> {
    let group_id = group.id;
    let guild_id = group.guild_id;
    let shard_index = object.shard_index;
    let root = object.root;
    let acknowledgement = if peer == local_id {
        node_blocking(node, move |node| {
            node.publish_verified_parity(&group, &information, &object)
        })
        .await?
    } else {
        p2p.publish_parity(peer, group, information, object).await?
    };
    acknowledgement.verify(STORAGE_ACKNOWLEDGEMENT_DOMAIN)?;
    if acknowledgement.signer != peer
        || acknowledgement.value.holder != peer
        || acknowledgement.value.operation_id != storage_operation_id(&group_id, shard_index)
        || acknowledgement.value.guild_id != guild_id
        || acknowledgement.value.group_id != group_id
        || acknowledgement.value.shard_index != shard_index
        || acknowledgement.value.root != root
    {
        bail!("parity holder returned an acknowledgement for another object");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn publish_p2p_checkpoint_object(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    peers: &[GuildPeer],
    object_kind: CheckpointObjectKind,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    bytes: &[u8],
) -> Result<()> {
    let total_pages = checked_catalog_page_count(bytes.len())?;
    for (page_index, page) in bytes.chunks(V1_CATALOG_PAGE_BYTES).enumerate() {
        let page = page.to_vec();
        let page_hash = *blake3::hash(&page).as_bytes();
        for peer in peers {
            let peer_id = peer.member.node_id;
            if peer_id == local_id {
                let page = page.clone();
                node_blocking(node.clone(), move |node| {
                    node.stage_checkpoint_page(
                        object_kind.as_str(),
                        &guild_id,
                        &checkpoint_hash,
                        page_index as u32,
                        total_pages,
                        &page_hash,
                        &page,
                    )
                })
                .await?;
            } else {
                p2p.put_checkpoint_page(
                    peer_id,
                    object_kind,
                    guild_id,
                    checkpoint_hash,
                    page_index as u32,
                    total_pages,
                    page_hash,
                    page.clone(),
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn node_blocking<T, F>(node: Arc<Mutex<Node>>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut Node) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        operation(&mut node)
    })
    .await
    .context("node worker failed")?
}

fn fail_dht_pending(pending: PendingDht, message: &str) {
    match pending {
        PendingDht::Put(response) | PendingDht::Provide(response) => {
            let _ = response.send(Err(anyhow::anyhow!(message.to_owned())));
        }
        PendingDht::Get { response, .. } => {
            let _ = response.send(Err(anyhow::anyhow!(message.to_owned())));
        }
        PendingDht::Providers { response, .. } => {
            let _ = response.send(Err(anyhow::anyhow!(message.to_owned())));
        }
    }
}

fn validate_outbound_response(
    response: SignedRecord<PeerResponseEnvelope>,
    pending: &PendingRequest,
) -> Result<PeerResponse> {
    response.verify(PEER_RESPONSE_DOMAIN)?;
    if response.signer != pending.recipient
        || response.signer.libp2p_peer_id()? != pending.peer
        || response.value.format_version != super::PEER_WIRE_FORMAT_VERSION
        || response.value.request_id != pending.request_id
        || response.value.recipient != pending.response_recipient
        || response.value.request_hash != pending.request_hash
    {
        bail!("libp2p peer response context mismatch");
    }
    response.value.result.map_err(anyhow::Error::new)
}

fn add_address_to_swarm(
    swarm: &mut Swarm<Behaviour>,
    address: Multiaddr,
) -> Result<(PeerId, Multiaddr)> {
    let peer = terminal_peer_id(&address)?;
    let address = add_known_address(swarm, peer, address)?;
    Ok((peer, address))
}

fn terminal_peer_id(address: &Multiaddr) -> Result<PeerId> {
    address
        .iter()
        .filter_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .last()
        .context("peer multiaddress has no /p2p identity")
}

fn add_known_address(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    address: Multiaddr,
) -> Result<Multiaddr> {
    let address = normalize_known_address(peer, address)?;
    swarm.add_peer_address(peer, address.clone());
    swarm
        .behaviour_mut()
        .kademlia
        .add_address(&peer, address.clone());
    Ok(address)
}

fn normalize_known_address(peer: PeerId, mut address: Multiaddr) -> Result<Multiaddr> {
    if address.iter().last() == Some(libp2p::multiaddr::Protocol::P2p(peer)) {
        address.pop();
    }
    if address.is_empty() {
        bail!("peer address has no transport components");
    }
    Ok(address)
}

#[allow(deprecated)]
fn remove_known_address(swarm: &mut Swarm<Behaviour>, peer: PeerId, address: &Multiaddr) {
    swarm.behaviour_mut().peer.remove_address(&peer, address);
    swarm
        .behaviour_mut()
        .kademlia
        .remove_address(&peer, address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::Seed;
    use request_response::Codec as _;

    fn config(node_id: NodeId) -> P2pConfig {
        P2pConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            external_addresses: Vec::new(),
            bootstrap_addresses: Vec::new(),
            relay_reservation_addresses: Vec::new(),
            enable_dht_maintenance: true,
            enable_relay_server: true,
            enable_hole_punching: true,
            public_endpoint: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            failure_domain: node_id.to_string(),
            configure_failure_domain: true,
            max_connections: 8,
        }
    }

    #[tokio::test]
    async fn production_peer_codec_rejects_oversized_frames() {
        let keys = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([76; 32]));
        let request = make_peer_request(
            &keys,
            None,
            PeerRequest::PutCheckpointPage {
                object_kind: CheckpointObjectKind::Body,
                guild_id: [1; 32],
                checkpoint_hash: [2; 32],
                page_index: 0,
                total_pages: 1,
                page_hash: [3; 32],
                bytes: vec![0; MAX_PEER_FRAME_BYTES],
            },
        )
        .unwrap();
        let encoded = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
        assert!(encoded.len() > MAX_PEER_FRAME_BYTES);
        let mut request_reader = futures::io::Cursor::new(encoded);
        assert!(
            peer_codec()
                .read_request(&P2P_PROTOCOL, &mut request_reader)
                .await
                .is_err()
        );

        let response = SignedRecord::sign(
            PEER_RESPONSE_DOMAIN,
            PeerResponseEnvelope {
                format_version: super::super::PEER_WIRE_FORMAT_VERSION,
                request_id: [4; 16],
                recipient: keys.node_id(),
                request_hash: [5; 32],
                result: Ok(PeerResponse::Bytes(vec![0; MAX_PEER_FRAME_BYTES])),
            },
            &keys,
        )
        .unwrap();
        let encoded = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
        assert!(encoded.len() > MAX_PEER_FRAME_BYTES);
        let mut response_reader = futures::io::Cursor::new(encoded);
        assert!(
            peer_codec()
                .read_response(&P2P_PROTOCOL, &mut response_reader)
                .await
                .is_err()
        );
    }

    #[test]
    fn relay_admission_uses_replaceable_membership_snapshot() {
        let allowed = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([74; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let denied = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([75; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let members = Arc::new(RwLock::new(BTreeSet::from([allowed])));
        let mut admission = guild_relay_admission(members.clone());
        let address: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        assert!(admission.try_next(allowed, &address, std::time::Instant::now()));
        assert!(!admission.try_next(denied, &address, std::time::Instant::now()));

        *members.write().unwrap() = BTreeSet::from([denied]);
        assert!(!admission.try_next(allowed, &address, std::time::Instant::now()));
        assert!(admission.try_next(denied, &address, std::time::Instant::now()));
    }

    #[test]
    fn generic_connection_event_does_not_erase_dcutr_classification() {
        assert_eq!(
            merge_established_path(Some(P2pPath::HolePunched), P2pPath::Direct, false),
            P2pPath::HolePunched
        );
        assert_eq!(
            merge_established_path(Some(P2pPath::Relayed), P2pPath::Direct, true),
            P2pPath::HolePunched
        );
        assert_eq!(
            merge_established_path(Some(P2pPath::Relayed), P2pPath::Direct, false),
            P2pPath::Direct,
        );
    }

    #[test]
    fn circuit_address_is_associated_with_its_destination() {
        let relay = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([70; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let destination = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let address: Multiaddr =
            format!("/ip4/127.0.0.1/udp/4100/quic-v1/p2p/{relay}/p2p-circuit/p2p/{destination}")
                .parse()
                .unwrap();
        assert_eq!(terminal_peer_id(&address).unwrap(), destination);
    }

    #[tokio::test]
    async fn learned_endpoint_cache_replaces_and_expires_addresses() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([73; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        let peer = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([72; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let first: Multiaddr = format!("/ip4/127.0.0.1/udp/4101/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let second: Multiaddr = format!("/ip4/127.0.0.1/udp/4102/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();

        event_loop
            .replace_learned_addresses(peer, vec![first], unix_seconds() + 300)
            .unwrap();
        assert_eq!(event_loop.learned_addresses[&peer].addresses.len(), 1);
        event_loop
            .replace_learned_addresses(peer, vec![second], unix_seconds() + 300)
            .unwrap();
        assert_eq!(
            event_loop.learned_addresses[&peer]
                .addresses
                .iter()
                .next()
                .unwrap()
                .to_string(),
            "/ip4/127.0.0.1/udp/4102/quic-v1"
        );

        event_loop
            .learned_addresses
            .get_mut(&peer)
            .unwrap()
            .expires_at = tokio::time::Instant::now();
        event_loop.expire_learned_addresses();
        assert!(!event_loop.learned_addresses.contains_key(&peer));
    }

    async fn listening_address(client: &P2pClient) -> Multiaddr {
        for _ in 0..100 {
            let status = client.status().await.unwrap();
            if let Some(address) = status.listen_addresses.first()
                && !address.contains("/udp/0/")
            {
                return address.parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("libp2p swarm did not start listening");
    }

    #[test]
    fn dht_endpoint_selection_rejects_forks_and_prefers_fresh_sequences() {
        let keys = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([77; 32]));
        let publisher = keys.node_id();
        let make = |sequence, port| {
            let value = mb_core::EndpointRecord {
                format_version: 1,
                publisher,
                sequence,
                expires_at_unix_seconds: unix_seconds() + 300,
                endpoints: vec![format!(
                    "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{}",
                    publisher.libp2p_peer_id().unwrap()
                )],
            };
            let signed =
                SignedRecord::sign(b"mutualbackup/endpoint-record/v1", value, &keys).unwrap();
            DhtRecord {
                publisher: None,
                value: canonical_bytes(&signed).unwrap(),
            }
        };
        let selected = select_endpoint_record(publisher, vec![make(1, 1), make(2, 2)])
            .unwrap()
            .unwrap();
        assert_eq!(selected.value.sequence, 2);
        assert!(select_endpoint_record(publisher, vec![make(3, 3), make(3, 4)]).is_err());
    }

    fn peer_endpoint(client: &P2pClient, address: Multiaddr) -> String {
        address
            .with(libp2p::multiaddr::Protocol::P2p(client.local_peer_id))
            .to_string()
    }

    async fn relayed_address(client: &P2pClient) -> Multiaddr {
        let mut last_status = None;
        for _ in 0..1500 {
            let status = client.status().await.unwrap();
            if let Some(address) = status
                .advertised_addresses
                .iter()
                .find(|address| address.contains("/p2p-circuit"))
            {
                let mut address: Multiaddr = address.parse().unwrap();
                let peer_id: PeerId = client.local_peer_id().parse().unwrap();
                if address.iter().last() != Some(libp2p::multiaddr::Protocol::P2p(peer_id)) {
                    address.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                }
                return address;
            }
            last_status = Some(status);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("libp2p relay reservation did not become ready: {last_status:?}");
    }

    async fn form_test_guild(
        nodes: &[Arc<Mutex<Node>>],
        clients: &[P2pClient],
        addresses: &[Multiaddr],
        endpoints: &[String],
    ) -> QuorumGuildGenesis {
        let coordinator_id = nodes[0].lock().unwrap().keys().node_id();
        nodes[0]
            .lock()
            .unwrap()
            .create_guild(vec![endpoints[0].clone()])
            .unwrap();
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        for index in 1..5 {
            let invite = nodes[0]
                .lock()
                .unwrap()
                .issue_guild_invite(vec![endpoints[0].clone()], expires)
                .unwrap();
            let local_peer = nodes[index]
                .lock()
                .unwrap()
                .begin_join_guild(invite.clone(), vec![endpoints[index].clone()])
                .unwrap();
            clients[index]
                .add_peer_address(coordinator_id, addresses[0].clone())
                .await
                .unwrap();
            clients[index]
                .join_guild(coordinator_id, invite, local_peer)
                .await
                .unwrap();
        }
        let (genesis, peers) = nodes[0].lock().unwrap().proposed_guild_genesis().unwrap();
        let mut signatures = vec![
            nodes[0]
                .lock()
                .unwrap()
                .sign_guild_genesis(&genesis)
                .unwrap(),
        ];
        for index in 1..5 {
            let peer_id = nodes[index].lock().unwrap().keys().node_id();
            clients[0]
                .add_peer_address(peer_id, addresses[index].clone())
                .await
                .unwrap();
            signatures.push(
                clients[0]
                    .propose_guild_genesis(peer_id, genesis.clone())
                    .await
                    .unwrap(),
            );
        }
        signatures.sort_by_key(|signature| signature.signer);
        let certificate = QuorumGuildGenesis {
            genesis,
            signatures,
        };
        certificate.verify().unwrap();
        for node in nodes.iter().skip(1) {
            let peer_id = node.lock().unwrap().keys().node_id();
            clients[0]
                .install_guild_genesis(peer_id, certificate.clone(), peers.clone())
                .await
                .unwrap();
        }
        nodes[0]
            .lock()
            .unwrap()
            .install_guild_genesis(certificate.clone(), peers)
            .unwrap();
        certificate
    }

    async fn active_test_guild_nodes(temp: &std::path::Path) -> Vec<Node> {
        let nodes = (73_u8..=77)
            .enumerate()
            .map(|(index, seed)| {
                Arc::new(Mutex::new(
                    Node::open(
                        temp.join(format!("guild-{index}")),
                        Seed::from_bytes([seed; 32]),
                    )
                    .unwrap(),
                ))
            })
            .collect::<Vec<_>>();
        let mut clients = Vec::new();
        let mut tasks = Vec::new();
        for node in &nodes {
            let node_id = node.lock().unwrap().keys().node_id();
            let mut initial_config = config(node_id);
            initial_config.enable_relay_server = false;
            let (client, event_loop) = build_p2p(node.clone(), initial_config).unwrap();
            clients.push(client);
            tasks.push(tokio::spawn(event_loop.run()));
        }
        let mut addresses = Vec::new();
        for client in &clients {
            addresses.push(listening_address(client).await);
        }
        let endpoints = clients
            .iter()
            .zip(&addresses)
            .map(|(client, address)| peer_endpoint(client, address.clone()))
            .collect::<Vec<_>>();
        form_test_guild(&nodes, &clients, &addresses, &endpoints).await;
        for client in &clients {
            client.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        drop(clients);
        nodes
            .into_iter()
            .map(|node| Arc::try_unwrap(node).ok().unwrap().into_inner().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn relay_reservation_recovers_from_a_concurrent_bootstrap_dial() {
        let temp = tempfile::tempdir().unwrap();
        let mut guild_nodes = active_test_guild_nodes(temp.path()).await.into_iter();
        let relay_node = guild_nodes.next().unwrap();
        let member_node = guild_nodes.next().unwrap();
        let relay_id = relay_node.keys().node_id();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_transport: Multiaddr = format!(
            "/ip4/127.0.0.1/udp/{}/quic-v1",
            socket.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        drop(socket);
        let mut relay_config = config(relay_id);
        relay_config.enable_hole_punching = false;
        relay_config.listen_addresses = vec![relay_transport.clone()];
        relay_config.external_addresses = vec![relay_transport];
        let (relay_client, relay_loop) =
            build_p2p(Arc::new(Mutex::new(relay_node)), relay_config).unwrap();
        let relay_task = tokio::spawn(relay_loop.run());
        let relay_address =
            listening_address(&relay_client)
                .await
                .with(libp2p::multiaddr::Protocol::P2p(
                    relay_client.local_peer_id().parse().unwrap(),
                ));

        let member_id = member_node.keys().node_id();
        let mut member_config = config(member_id);
        member_config.enable_relay_server = false;
        member_config.enable_hole_punching = false;
        member_config.bootstrap_addresses = vec![relay_address.clone()];
        member_config.relay_reservation_addresses = vec![relay_address];
        let (member_client, member_loop) =
            build_p2p(Arc::new(Mutex::new(member_node)), member_config).unwrap();
        let member_task = tokio::spawn(member_loop.run());
        assert!(
            relayed_address(&member_client)
                .await
                .to_string()
                .contains("/p2p-circuit")
        );

        member_client.shutdown().await.unwrap();
        relay_client.shutdown().await.unwrap();
        member_task.await.unwrap().unwrap();
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn quic_transport_uses_the_seed_identity_for_application_requests() {
        let temp = tempfile::tempdir().unwrap();
        let first_seed = Seed::from_bytes([71; 32]);
        let second_seed = Seed::from_bytes([72; 32]);
        let first_node = Node::open(temp.path().join("first"), first_seed).unwrap();
        let second_node = Node::open(temp.path().join("second"), second_seed).unwrap();
        let first_id = first_node.keys().node_id();
        let second_id = second_node.keys().node_id();
        let (first_client, first_loop) =
            build_p2p(Arc::new(Mutex::new(first_node)), config(first_id)).unwrap();
        let (second_client, second_loop) =
            build_p2p(Arc::new(Mutex::new(second_node)), config(second_id)).unwrap();
        let first_task = tokio::spawn(first_loop.run());
        let second_task = tokio::spawn(second_loop.run());

        let second_address = listening_address(&second_client).await;
        first_client
            .add_peer_address(second_id, second_address)
            .await
            .unwrap();
        let profile = first_client.profile(second_id).await.unwrap();
        assert_eq!(profile.member.node_id, second_id);
        assert_eq!(
            second_id.libp2p_peer_id().unwrap().to_string(),
            second_client.local_peer_id()
        );
        let status = first_client.status().await.unwrap();
        let connection = status
            .peers
            .iter()
            .find(|peer| peer.peer_id == second_client.local_peer_id())
            .unwrap();
        assert_eq!(connection.last_application_path, Some(P2pPath::Direct));
        assert!(connection.application_bytes_sent > 0);
        assert!(connection.application_bytes_received > 0);

        let record_key = b"mutualbackup-test-record".to_vec();
        first_client
            .put_record(record_key.clone(), b"signed-value".to_vec())
            .await
            .unwrap();
        let records = second_client.get_record(record_key.clone()).await.unwrap();
        assert!(records.iter().any(|record| record.value == b"signed-value"));
        first_client
            .start_providing(record_key.clone())
            .await
            .unwrap();
        let providers = second_client.get_providers(record_key).await.unwrap();
        assert!(providers.contains(&first_client.local_peer_id()));

        first_client.shutdown().await.unwrap();
        second_client.shutdown().await.unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn peer_worker_limit_rejects_overload_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let first_node = Node::open(temp.path().join("first"), Seed::from_bytes([68; 32])).unwrap();
        let second_node =
            Node::open(temp.path().join("second"), Seed::from_bytes([69; 32])).unwrap();
        let first_id = first_node.keys().node_id();
        let second_id = second_node.keys().node_id();
        let (first_client, first_loop) =
            build_p2p(Arc::new(Mutex::new(first_node)), config(first_id)).unwrap();
        let mut second_config = config(second_id);
        second_config.max_connections = 1;
        let (second_client, second_loop) =
            build_p2p(Arc::new(Mutex::new(second_node)), second_config).unwrap();
        let held_permit = second_loop
            .inbound_permits
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let first_task = tokio::spawn(first_loop.run());
        let second_task = tokio::spawn(second_loop.run());

        let second_address = listening_address(&second_client).await;
        first_client
            .add_peer_address(second_id, second_address)
            .await
            .unwrap();
        let error = first_client.profile(second_id).await.unwrap_err();
        assert!(error.to_string().contains("capacity is exhausted"));
        drop(held_permit);
        assert_eq!(
            first_client
                .profile(second_id)
                .await
                .unwrap()
                .member
                .node_id,
            second_id
        );

        first_client.shutdown().await.unwrap();
        second_client.shutdown().await.unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_circuit_supports_application_requests_and_dcutr_upgrade() {
        let temp = tempfile::tempdir().unwrap();
        let mut guild_nodes = active_test_guild_nodes(temp.path()).await.into_iter();
        let relay_node = guild_nodes.next().unwrap();
        let first_node = guild_nodes.next().unwrap();
        let second_node = guild_nodes.next().unwrap();
        let fallback_node = guild_nodes.next().unwrap();
        let _offline_member = guild_nodes.next().unwrap();
        let relay_id = relay_node.keys().node_id();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_port = socket.local_addr().unwrap().port();
        drop(socket);
        let relay_transport: Multiaddr = format!("/ip4/127.0.0.1/udp/{relay_port}/quic-v1")
            .parse()
            .unwrap();
        let mut relay_config = config(relay_id);
        relay_config.listen_addresses = vec![relay_transport.clone()];
        relay_config.external_addresses = vec![relay_transport];
        let (relay_client, relay_loop) =
            build_p2p(Arc::new(Mutex::new(relay_node)), relay_config).unwrap();
        let relay_task = tokio::spawn(relay_loop.run());
        let relay_address =
            listening_address(&relay_client)
                .await
                .with(libp2p::multiaddr::Protocol::P2p(
                    relay_client.local_peer_id().parse().unwrap(),
                ));

        let first_id = first_node.keys().node_id();
        let second_id = second_node.keys().node_id();
        let mut first_config = config(first_id);
        let first_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let first_transport: Multiaddr = format!(
            "/ip4/127.0.0.1/udp/{}/quic-v1",
            first_socket.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        drop(first_socket);
        first_config.listen_addresses = vec![first_transport.clone()];
        first_config.external_addresses = vec![first_transport];
        first_config.enable_relay_server = false;
        first_config.relay_reservation_addresses = vec![relay_address.clone()];
        let mut second_config = config(second_id);
        let second_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let second_transport: Multiaddr = format!(
            "/ip4/127.0.0.1/udp/{}/quic-v1",
            second_socket.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        drop(second_socket);
        second_config.listen_addresses = vec![second_transport.clone()];
        second_config.external_addresses = vec![second_transport];
        second_config.enable_relay_server = false;
        second_config.relay_reservation_addresses = vec![relay_address.clone()];
        let (first_client, first_loop) =
            build_p2p(Arc::new(Mutex::new(first_node)), first_config).unwrap();
        let (second_client, second_loop) =
            build_p2p(Arc::new(Mutex::new(second_node)), second_config).unwrap();
        let first_task = tokio::spawn(first_loop.run());
        let second_task = tokio::spawn(second_loop.run());

        let second_relayed = relayed_address(&second_client).await;
        first_client
            .add_peer_address(second_id, second_relayed)
            .await
            .unwrap();
        let profile = first_client.profile(second_id).await.unwrap();
        assert_eq!(profile.member.node_id, second_id);
        let mut saw_hole_punch = false;
        for _ in 0..500 {
            let status = first_client.status().await.unwrap();
            saw_hole_punch = status.peers.iter().any(|peer| {
                peer.peer_id == second_client.local_peer_id()
                    && peer.active_paths.contains(&P2pPath::HolePunched)
                    && !peer
                        .active_paths
                        .iter()
                        .any(|path| matches!(path, P2pPath::Relayed | P2pPath::RelayFallback))
            });
            if saw_hole_punch {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            saw_hole_punch,
            "DCUtR did not replace the relay circuit with a direct QUIC path"
        );
        for _ in 0..10 {
            first_client.profile(second_id).await.unwrap();
            let status = first_client.status().await.unwrap();
            if status.peers.iter().any(|peer| {
                peer.peer_id == second_client.local_peer_id()
                    && peer.last_application_path == Some(P2pPath::HolePunched)
            }) {
                break;
            }
        }
        let status = first_client.status().await.unwrap();
        assert!(status.peers.iter().any(|peer| {
            peer.peer_id == second_client.local_peer_id()
                && peer.last_application_path == Some(P2pPath::HolePunched)
                && peer.application_bytes_sent > 0
                && peer.application_bytes_received > 0
        }));

        let fallback_id = fallback_node.keys().node_id();
        let mut fallback_config = config(fallback_id);
        fallback_config.listen_addresses.clear();
        fallback_config.enable_relay_server = false;
        fallback_config.enable_hole_punching = false;
        fallback_config.relay_reservation_addresses = vec![relay_address.clone()];
        let (fallback_client, fallback_loop) =
            build_p2p(Arc::new(Mutex::new(fallback_node)), fallback_config).unwrap();
        let fallback_task = tokio::spawn(fallback_loop.run());
        first_client
            .add_peer_address(fallback_id, relayed_address(&fallback_client).await)
            .await
            .unwrap();
        let profile = first_client.profile(fallback_id).await.unwrap();
        assert_eq!(profile.member.node_id, fallback_id);
        let status = first_client.status().await.unwrap();
        assert!(
            status.peers.iter().any(|peer| {
                peer.peer_id == fallback_client.local_peer_id()
                    && peer.last_application_path == Some(P2pPath::RelayFallback)
                    && peer.application_bytes_sent > 0
                    && peer.application_bytes_received > 0
            }),
            "fallback request did not use the relay circuit: {status:?}"
        );

        let nonmember_node =
            Node::open(temp.path().join("nonmember"), Seed::from_bytes([90; 32])).unwrap();
        let nonmember_id = nonmember_node.keys().node_id();
        let mut nonmember_config = config(nonmember_id);
        nonmember_config.enable_relay_server = false;
        nonmember_config.relay_reservation_addresses = vec![relay_address];
        let (nonmember_client, nonmember_loop) =
            build_p2p(Arc::new(Mutex::new(nonmember_node)), nonmember_config).unwrap();
        let nonmember_task = tokio::spawn(nonmember_loop.run());
        for _ in 0..200 {
            assert!(
                nonmember_client
                    .status()
                    .await
                    .unwrap()
                    .advertised_addresses
                    .iter()
                    .all(|address| !address.contains("/p2p-circuit")),
                "nonmember obtained a guild-only relay reservation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        first_client.shutdown().await.unwrap();
        second_client.shutdown().await.unwrap();
        fallback_client.shutdown().await.unwrap();
        nonmember_client.shutdown().await.unwrap();
        relay_client.shutdown().await.unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
        fallback_task.await.unwrap().unwrap();
        nonmember_task.await.unwrap().unwrap();
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn five_peers_install_and_reopen_one_unanimous_guild_genesis() {
        let temp = tempfile::tempdir().unwrap();
        let seeds = (81_u8..=85)
            .map(|value| Seed::from_bytes([value; 32]))
            .collect::<Vec<_>>();
        let mut nodes = Vec::new();
        let mut clients = Vec::new();
        let mut tasks = Vec::new();
        for (index, seed) in seeds.iter().cloned().enumerate() {
            let node = Node::open(temp.path().join(format!("node-{index}")), seed).unwrap();
            let node_id = node.keys().node_id();
            let node = Arc::new(Mutex::new(node));
            let (client, event_loop) = build_p2p(node.clone(), config(node_id)).unwrap();
            nodes.push(node);
            clients.push(client);
            tasks.push(tokio::spawn(event_loop.run()));
        }

        let addresses = futures::future::join_all(clients.iter().map(listening_address)).await;
        let endpoints = clients
            .iter()
            .zip(addresses.iter().cloned())
            .map(|(client, address)| peer_endpoint(client, address))
            .collect::<Vec<_>>();
        let certificate = form_test_guild(&nodes, &clients, &addresses, &endpoints).await;

        for client in &clients {
            client.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        drop(clients);
        drop(nodes);
        for (index, seed) in seeds.iter().cloned().enumerate() {
            let node = Node::open(temp.path().join(format!("node-{index}")), seed).unwrap();
            let reopened = node.installed_guild_certificate().unwrap().unwrap();
            assert_eq!(reopened, certificate);
            reopened.verify().unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires an explicitly provisioned reflink test filesystem"]
    async fn repeated_multi_owner_backups_commit_over_quic() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
        let run_root =
            std::path::PathBuf::from(test_root).join(format!("p2p-data-path-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&run_root).unwrap();
        let seeds = (101_u8..=105)
            .map(|value| Seed::from_bytes([value; 32]))
            .collect::<Vec<_>>();
        let mut nodes = Vec::new();
        let mut clients = Vec::new();
        let mut tasks = Vec::new();
        for (index, seed) in seeds.iter().cloned().enumerate() {
            let node = Node::open(run_root.join(format!("node-{index}")), seed).unwrap();
            let node_id = node.keys().node_id();
            let node = Arc::new(Mutex::new(node));
            let (client, event_loop) = build_p2p(node.clone(), config(node_id)).unwrap();
            nodes.push(node);
            clients.push(client);
            tasks.push(tokio::spawn(event_loop.run()));
        }
        let addresses = futures::future::join_all(clients.iter().map(listening_address)).await;
        let endpoints = clients
            .iter()
            .zip(addresses.iter().cloned())
            .map(|(client, address)| peer_endpoint(client, address))
            .collect::<Vec<_>>();
        let genesis = form_test_guild(&nodes, &clients, &addresses, &endpoints).await;

        let mut watcher_task = None;
        for (owner_index, expected_generation) in [(1_usize, 1_u64), (2, 2)] {
            let source = run_root.join(format!("source-{owner_index}"));
            std::fs::create_dir_all(source.join("documents")).unwrap();
            std::fs::write(
                source.join("documents/content.bin"),
                (0..90_000)
                    .map(|offset| ((offset + owner_index * 29) % 251) as u8)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let owner_id = nodes[owner_index].lock().unwrap().keys().node_id();
            nodes[owner_index]
                .lock()
                .unwrap()
                .add_protected_root(&source)
                .unwrap();
            if owner_index == 2 {
                watcher_task = Some(tokio::spawn(crate::run_root_watcher(
                    nodes[owner_index].clone(),
                )));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let descriptor = nodes[owner_index]
                .lock()
                .unwrap()
                .prepare_protected_backup()
                .unwrap();
            let queued = nodes[0]
                .lock()
                .unwrap()
                .enqueue_backup(owner_id, descriptor.clone())
                .unwrap();
            let checkpoint_hash = commit_backup_job(nodes[0].clone(), &clients[0], &queued)
                .await
                .unwrap();
            nodes[0]
                .lock()
                .unwrap()
                .complete_backup_job(&descriptor, checkpoint_hash)
                .unwrap();
            for node in &nodes {
                let checkpoint = node
                    .lock()
                    .unwrap()
                    .current_checkpoint(genesis.genesis.guild_id)
                    .unwrap()
                    .unwrap();
                assert_eq!(checkpoint.checkpoint.generation, expected_generation);
                assert_eq!(checkpoint.checkpoint.genesis_hash, genesis.hash().unwrap());
            }
        }
        let final_checkpoint = nodes[0]
            .lock()
            .unwrap()
            .current_checkpoint(genesis.genesis.guild_id)
            .unwrap()
            .unwrap();
        assert_eq!(final_checkpoint.checkpoint.revisions.len(), 2);
        assert!(final_checkpoint.checkpoint.coding_groups.len() >= 4);
        let forgotten_sector = final_checkpoint
            .checkpoint
            .revisions
            .iter()
            .find(|revision| revision.value.owner == nodes[2].lock().unwrap().keys().node_id())
            .unwrap()
            .value
            .metadata_sectors[0]
            .id;
        nodes[2]
            .lock()
            .unwrap()
            .forget_local_sector(&forgotten_sector)
            .unwrap();
        let healthy_restore = run_root.join("healthy-restore-node-2");
        restore_snapshot_with_p2p(nodes[2].clone(), &clients[2], None, &healthy_restore)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(healthy_restore.join("documents/content.bin")).unwrap(),
            (0..90_000)
                .map(|offset| ((offset + 58) % 251) as u8)
                .collect::<Vec<_>>()
        );
        assert!(!nodes[2].lock().unwrap().root_dirty().unwrap());
        std::fs::write(
            run_root.join("source-2/documents/content.bin"),
            b"watcher-observed-change",
        )
        .unwrap();
        for _ in 0..100 {
            if nodes[2].lock().unwrap().root_dirty().unwrap() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(nodes[2].lock().unwrap().root_dirty().unwrap());
        watcher_task.take().unwrap().abort();

        for _ in 0..6 {
            let passes = nodes
                .iter()
                .cloned()
                .zip(clients.iter())
                .map(|(node, client)| publish_dht_once(node, client));
            let _ = futures::future::join_all(passes).await;
            if nodes
                .iter()
                .all(|node| node.lock().unwrap().seed_recovery_ready().unwrap())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(
            nodes
                .iter()
                .all(|node| node.lock().unwrap().seed_recovery_ready().unwrap()),
            "all subjects must find current bundles from at least three other publishers"
        );
        let final_hash = final_checkpoint.hash().unwrap();
        let expires = unix_seconds() + 300;
        nodes[0]
            .lock()
            .unwrap()
            .update_seed_recovery_readiness(
                final_hash,
                vec![
                    (nodes[1].lock().unwrap().keys().node_id(), expires),
                    (nodes[2].lock().unwrap().keys().node_id(), expires),
                ],
            )
            .unwrap();
        assert!(!nodes[0].lock().unwrap().seed_recovery_ready().unwrap());
        let expired = unix_seconds().saturating_sub(1);
        nodes[0]
            .lock()
            .unwrap()
            .update_seed_recovery_readiness(
                final_hash,
                vec![
                    (nodes[1].lock().unwrap().keys().node_id(), expired),
                    (nodes[2].lock().unwrap().keys().node_id(), expired),
                    (nodes[3].lock().unwrap().keys().node_id(), expired),
                ],
            )
            .unwrap();
        assert!(!nodes[0].lock().unwrap().seed_recovery_ready().unwrap());

        clients[1].shutdown().await.unwrap();
        clients[4].shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let lost_source = run_root.join("source-1");
        std::fs::remove_dir_all(&lost_source).unwrap();
        let recovered_state = run_root.join("recovered-node-1");
        let restored = run_root.join("restored-node-1");
        let recovered_node = Node::open(&recovered_state, seeds[1].clone()).unwrap();
        let recovered_id = recovered_node.keys().node_id();
        let recovered_node = Arc::new(Mutex::new(recovered_node));
        let mut recovery_config = config(recovered_id);
        recovery_config.failure_domain.clear();
        recovery_config.configure_failure_domain = false;
        recovery_config.bootstrap_addresses = vec![endpoints[0].parse().unwrap()];
        let (recovery_client, recovery_loop) =
            build_p2p(recovered_node.clone(), recovery_config).unwrap();
        let recovery_task = tokio::spawn(recovery_loop.run());
        let recovered = recover_from_dht(recovered_node.clone(), &recovery_client, &restored)
            .await
            .unwrap();
        assert_eq!(recovered.generation, 2);
        assert_eq!(
            std::fs::read(restored.join("documents/content.bin")).unwrap(),
            (0..90_000)
                .map(|offset| ((offset + 29) % 251) as u8)
                .collect::<Vec<_>>()
        );
        publish_dht_once(recovered_node.clone(), &recovery_client)
            .await
            .unwrap();
        let recovered_peer_id = recovery_client.local_peer_id();
        let endpoint = select_endpoint_record(
            recovered_id,
            clients[0]
                .get_record(endpoint_record_key(&recovered_peer_id))
                .await
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            endpoint.value.endpoints,
            advertised_p2p_endpoints(&recovery_client).await.unwrap()
        );
        recovery_client.shutdown().await.unwrap();
        recovery_task.await.unwrap().unwrap();
        drop(recovered_node);

        for client in &clients {
            let _ = client.shutdown().await;
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        drop(clients);
        drop(nodes);
        std::fs::remove_dir_all(run_root).unwrap();
    }
}
