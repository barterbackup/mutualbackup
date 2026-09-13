use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{
    DialOpts as TransportDialOpts, ListenerId, OptionalTransport, Transport, TransportError,
    TransportEvent,
};
use libp2p::core::{ConnectedPoint, upgrade};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::behaviour::{FromSwarm, NewExternalAddrCandidate};
use libp2p::swarm::dial_opts::{DialOpts as SwarmDialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, StreamProtocol, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, dcutr, identify, kad, noise, ping, quic,
    relay, request_response, yamux,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

use mb_core::{
    CodingGroup, GuildCheckpoint, GuildGenesis, GuildInvite, InformationRole, Member,
    MemberSignature, NodeId, ParityRole, QuorumCheckpoint, QuorumGuildGenesis,
    RECOVERY_LOCATOR_DOMAIN, STORAGE_ACKNOWLEDGEMENT_DOMAIN, SectorId, SectorRef, ShardRole,
    SignedRecord, StorageAcknowledgement, UserRevision, V1_CATALOG_PAGE_BYTES,
    V1_MAX_CATALOG_BYTES, V1_MAX_CATALOG_PAGES, V1_MAX_CODING_GROUPS, V1_MAX_ENDPOINT_BYTES,
    V1_MAX_ENDPOINTS_PER_PEER, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS, V1_SECTOR_SIZE,
    canonical_bytes, decode_canonical, encode_3_2, open_recovery_record, sector_root,
};
use mb_store::ParityObject;
use uuid::Uuid;

use crate::node::{CheckpointRecoveryObservation, DhtRecordObservation, GuildPhase, SnapshotInfo};

#[cfg(test)]
use super::onion_listener_address;
use super::tor::is_canonical_onion_address;
use super::{
    BackupDescriptor, BackupJob, CheckpointObjectKind, DhtSequenceFloors, GuildPeer,
    MAX_PEER_FRAME_BYTES, Node, NodeServerConfig, NodeService, PEER_RESPONSE_DOMAIN, PeerRequest,
    PeerRequestEnvelope, PeerResponse, PeerResponseEnvelope, checked_catalog_page_count,
    make_peer_request, peer_error_response, process_peer_request, storage_operation_id,
};
use super::{
    TorMode, TorTransport, is_onion_address, onion_address_matches_node, onion_address_matches_peer,
};

const P2P_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/peer/1");
const IDENTIFY_PROTOCOL: &str = "/mutualbackup/identify/1";
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/kad/1");
const COMMAND_CAPACITY: usize = 128;
const DHT_TTL: Duration = Duration::from_secs(15 * 60);
const DHT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DHT_MAX_PACKET_BYTES: usize = 128 * 1024;
// Three replicas survive any two losses in the fixed five-node profile. Asking
// Kademlia for all five makes recovery wait for the two nodes it is designed to
// tolerate losing before it can use the three live publishers.
const DHT_REPLICATION_FACTOR: usize = 3;
const BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const RELAY_RESERVATION_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_RETIREMENT_GRACE: Duration = Duration::from_millis(500);
const RELAY_RETIREMENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const LEARNED_ENDPOINT_EXPIRY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_DHT_RECORDS_PER_QUERY: usize = 64;
const MAX_DHT_PROVIDERS_PER_QUERY: usize = 64;
const MAX_LEARNED_ENDPOINT_PEERS: usize = 1_024;
const MAX_OPPORTUNISTIC_ENDPOINT_PEERS: usize = 256;
const MAX_ENDPOINTS_PER_PEER: usize = V1_MAX_ENDPOINTS_PER_PEER;
const MAX_ENDPOINT_BYTES: usize = V1_MAX_ENDPOINT_BYTES;
const MAX_BOOTSTRAP_ADDRESSES: usize = 64;
const MAX_RECOVERY_ADDRESS_SCOPES: usize = 4;
const MAX_RECOVERY_ADDRESS_PEERS: usize = 64;
const MAX_RECOVERY_QUARANTINED_PEERS: usize =
    MAX_RECOVERY_ADDRESS_SCOPES * MAX_RECOVERY_ADDRESS_PEERS;
const MAX_RELAY_RESERVATIONS: usize = 5;
const MAX_RELAY_CIRCUITS: usize = 8;
const MAX_RELAY_CIRCUIT_BYTES: u64 = 8 * 1024 * 1024;
const DHT_RECOVERY_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DHT_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const SHARD_FETCH_ATTEMPTS: usize = 3;
const PEER_EXCHANGE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_EXCHANGED_ENDPOINT_RECORDS: usize = 64;
const PREFERRED_PATH_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const LOGICAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const REQUEST_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
const MAX_REQUEST_TRANSPORT_ATTEMPTS: u8 = 6;
const CLOSED_CONNECTION_PATH_RETENTION: Duration = Duration::from_secs(40);
const TRANSPORT_PROMOTION_GRACE: Duration = Duration::from_millis(500);
const MAX_SESSION_HISTORY: usize = 256;

type RelayMembers = Arc<RwLock<BTreeSet<PeerId>>>;

struct PolicyTransport<T> {
    inner: T,
    mode: TorMode,
}

impl<T> PolicyTransport<T> {
    fn new(inner: T, mode: TorMode) -> Self {
        Self { inner, mode }
    }
}

impl<T> Transport for PolicyTransport<T>
where
    T: Transport + Unpin,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> std::result::Result<(), TransportError<Self::Error>> {
        if !transport_address_allowed(self.mode, &address) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.inner.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        options: TransportDialOpts,
    ) -> std::result::Result<Self::Dial, TransportError<Self::Error>> {
        if !transport_address_allowed(self.mode, &address) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.inner.dial(address, options)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub external_addresses: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub relay_reservation_addresses: Vec<Multiaddr>,
    pub enable_dht_maintenance: bool,
    pub enable_relay_server: bool,
    pub enable_hole_punching: bool,
    pub enable_port_mapping: bool,
    pub public_endpoint: String,
    pub failure_domain: String,
    pub configure_failure_domain: bool,
    pub max_connections: usize,
    pub tor_mode: TorMode,
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
    Tor,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pPathTransfer {
    pub path: P2pPath,
    pub application_bytes_sent: u64,
    pub application_bytes_received: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pPeerStatus {
    pub peer_id: String,
    pub active_paths: Vec<P2pPath>,
    pub last_application_path: Option<P2pPath>,
    pub application_bytes_sent: u64,
    pub application_bytes_received: u64,
    pub path_transfers: Vec<P2pPathTransfer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum P2pSessionDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum P2pSessionOutcome {
    Closed,
    Collapsed,
    TransportError,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pActiveSession {
    pub sequence: u64,
    pub peer_id: String,
    pub path: P2pPath,
    pub direction: P2pSessionDirection,
    pub opened_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pSessionHistory {
    pub sequence: u64,
    pub peer_id: String,
    pub path: P2pPath,
    pub direction: P2pSessionDirection,
    pub opened_at_unix_seconds: u64,
    pub closed_at_unix_seconds: u64,
    pub duration_millis: u64,
    pub outcome: P2pSessionOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct P2pPathMetrics {
    pub path: P2pPath,
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    pub dial_failures: u64,
    pub requests_succeeded: u64,
    pub requests_failed: u64,
    pub request_latency_millis_total: u64,
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
    pub tor_mode: TorMode,
    pub onion_service_configured: bool,
    pub onion_service_reachable: bool,
    pub port_mapping_enabled: bool,
    pub port_mapping_external_address: Option<String>,
    pub degraded: Vec<String>,
    pub listen_addresses: Vec<String>,
    pub advertised_addresses: Vec<String>,
    pub peers: Vec<P2pPeerStatus>,
    pub active_sessions: Vec<P2pActiveSession>,
    pub recent_sessions: Vec<P2pSessionHistory>,
    pub path_metrics: Vec<P2pPathMetrics>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pStartup {
    pub direct_listeners_active: usize,
    pub relay_reservations_active: usize,
    pub onion_service_reachable: bool,
    pub degraded: Vec<String>,
}

pub type P2pStartupReceiver = oneshot::Receiver<std::result::Result<P2pStartup, String>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PortMappingListenerState {
    Pending,
    Active(NonZeroU16),
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRecord {
    pub publisher: Option<String>,
    pub value: Vec<u8>,
}

#[derive(Clone)]
pub struct P2pClient {
    local_peer_id: PeerId,
    commands: mpsc::Sender<Command>,
    request_cancellations: mpsc::UnboundedSender<Uuid>,
    outbound_permits: Arc<Semaphore>,
    cold_recovery_permit: Arc<Semaphore>,
    port_mapping_listener_state: watch::Receiver<PortMappingListenerState>,
}

pub struct P2pEventLoop {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    request_cancellations: mpsc::UnboundedReceiver<Uuid>,
    inbound_results: mpsc::Receiver<InboundResult>,
    inbound_sender: mpsc::Sender<InboundResult>,
    inbound_permits: Arc<Semaphore>,
    pending_requests: HashMap<request_response::OutboundRequestId, PendingRequest>,
    queued_requests: VecDeque<PendingRequest>,
    active_inbound_requests: HashMap<request_response::InboundRequestId, PeerId>,
    pending_response_bytes:
        HashMap<request_response::InboundRequestId, (PeerId, Option<P2pPath>, u64)>,
    pending_dht: HashMap<kad::QueryId, PendingDht>,
    service: Arc<NodeService>,
    server_config: NodeServerConfig,
    advertised_addresses: Vec<Multiaddr>,
    port_mapping_enabled: bool,
    mapped_external_address: Option<Multiaddr>,
    port_mapping_listener: Option<ListenerId>,
    port_mapping_listener_active: bool,
    port_mapping_listener_state: watch::Sender<PortMappingListenerState>,
    direct_listeners: HashMap<ListenerId, Multiaddr>,
    active_direct_listeners: HashSet<ListenerId>,
    closed_direct_listeners: HashSet<ListenerId>,
    tor_mode: TorMode,
    tor_listener: Option<(ListenerId, Multiaddr)>,
    active_tor_listener: bool,
    bootstrap_addresses: Vec<Multiaddr>,
    enable_dht_maintenance: bool,
    bootstrap_retry: tokio::time::Interval,
    relay_reservations: Vec<Multiaddr>,
    relay_reservation_peers: HashSet<PeerId>,
    relay_listeners: HashMap<ListenerId, Multiaddr>,
    active_relay_listeners: HashSet<ListenerId>,
    relay_retry: tokio::time::Interval,
    relay_retirement: HashMap<ConnectionId, (PeerId, tokio::time::Instant)>,
    relay_retirement_tick: tokio::time::Interval,
    relay_members: RelayMembers,
    persistent_addresses: HashMap<PeerId, BTreeSet<Multiaddr>>,
    installed_policy_addresses: HashMap<PeerId, BTreeSet<Multiaddr>>,
    fallback_tiers: HashMap<PeerId, u8>,
    policy_dials: HashMap<ConnectionId, PolicyDial>,
    transport_promotions: HashMap<PeerId, TransportPromotion>,
    preferred_path_retry: tokio::time::Interval,
    request_maintenance: tokio::time::Interval,
    learned_addresses: HashMap<PeerId, LearnedAddresses>,
    opportunistic_addresses: HashMap<PeerId, LearnedAddresses>,
    recovery_addresses: HashMap<Uuid, RecoveryAddresses>,
    recovery_quarantine: HashMap<PeerId, tokio::time::Instant>,
    learned_endpoint_expiry: tokio::time::Interval,
    connection_paths: HashMap<ConnectionId, (PeerId, P2pPath)>,
    closed_connection_paths: HashMap<ConnectionId, ClosedConnectionPath>,
    connection_dialers: HashMap<ConnectionId, bool>,
    duplicate_retirement: HashMap<ConnectionId, (PeerId, tokio::time::Instant)>,
    next_session_sequence: u64,
    sessions: HashMap<ConnectionId, SessionRuntime>,
    recent_sessions: VecDeque<P2pSessionHistory>,
    path_metrics: BTreeMap<P2pPath, PathMetrics>,
    collapsing_connections: HashSet<ConnectionId>,
    unhealthy_connections: HashSet<ConnectionId>,
    last_application_paths: HashMap<PeerId, P2pPath>,
    transfer_counters: HashMap<PeerId, TransferCounters>,
    path_transfer_counters: HashMap<PeerId, BTreeMap<P2pPath, TransferCounters>>,
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
    AddLearnedAddress {
        peer: PeerId,
        address: Multiaddr,
        response: oneshot::Sender<Result<()>>,
    },
    AddRecoveryAddresses {
        scope: Uuid,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
        response: oneshot::Sender<Result<()>>,
    },
    ClearRecoveryAddresses {
        scope: Uuid,
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
    SetMappedExternalAddress {
        address: Option<Multiaddr>,
        response: oneshot::Sender<Result<()>>,
    },
    #[cfg(test)]
    ClosePortMappingListener {
        response: oneshot::Sender<Result<()>>,
    },
    Request {
        cancellation_id: Uuid,
        peer: PeerId,
        recipient: NodeId,
        request: Box<PeerRequest>,
        response: oneshot::Sender<Result<PeerResponse>>,
        permit: OwnedSemaphorePermit,
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
    cancellation_id: Uuid,
    peer: PeerId,
    recipient: NodeId,
    response_recipient: NodeId,
    request: SignedRecord<PeerRequestEnvelope>,
    request_id: [u8; 16],
    request_hash: [u8; 32],
    request_bytes: u64,
    transport_tier: u8,
    attempts: u8,
    deadline: tokio::time::Instant,
    started_at: tokio::time::Instant,
    response: Option<oneshot::Sender<Result<PeerResponse>>>,
    _permit: OwnedSemaphorePermit,
}

impl PendingRequest {
    fn caller_waiting(&self) -> bool {
        self.response
            .as_ref()
            .is_some_and(|response| !response.is_closed())
    }

    fn finish(&mut self, result: Result<PeerResponse>) {
        if let Some(response) = self.response.take() {
            let _ = response.send(result);
        }
    }
}

struct RequestCancellation {
    id: Option<Uuid>,
    sender: mpsc::UnboundedSender<Uuid>,
}

impl RequestCancellation {
    fn new(id: Uuid, sender: mpsc::UnboundedSender<Uuid>) -> Self {
        Self {
            id: Some(id),
            sender,
        }
    }

    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let _ = self.sender.send(id);
        }
    }
}

struct InboundResult {
    peer: PeerId,
    path: Option<P2pPath>,
    request_id: request_response::InboundRequestId,
    channel: request_response::ResponseChannel<SignedRecord<PeerResponseEnvelope>>,
    response: Result<SignedRecord<PeerResponseEnvelope>>,
}

struct LearnedAddresses {
    addresses: BTreeSet<Multiaddr>,
    expires_at: tokio::time::Instant,
}

struct RecoveryAddresses {
    addresses: HashMap<PeerId, BTreeSet<Multiaddr>>,
    expires_at: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyDialKind {
    Selected,
    PreferredProbe,
}

#[derive(Clone, Copy, Debug)]
struct PolicyDial {
    peer: PeerId,
    tier: u8,
    path: P2pPath,
    kind: PolicyDialKind,
}

#[derive(Clone, Copy, Debug)]
struct TransportPromotion {
    tier: u8,
    deadline: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug)]
struct ClosedConnectionPath {
    peer: PeerId,
    path: P2pPath,
    expires_at: tokio::time::Instant,
}

struct SessionRuntime {
    sequence: u64,
    peer: PeerId,
    path: P2pPath,
    direction: P2pSessionDirection,
    opened_at_unix_seconds: u64,
    opened_at: tokio::time::Instant,
}

#[derive(Default)]
struct PathMetrics {
    sessions_opened: u64,
    sessions_closed: u64,
    dial_failures: u64,
    requests_succeeded: u64,
    requests_failed: u64,
    request_latency_millis_total: u64,
    application_bytes_sent: u64,
    application_bytes_received: u64,
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

fn merge_established_path(recorded: Option<P2pPath>, generic: P2pPath) -> P2pPath {
    match (recorded, generic) {
        (Some(P2pPath::HolePunched), _) => P2pPath::HolePunched,
        _ => generic,
    }
}

fn address_allowed_by_tor_mode(mode: TorMode, address: &Multiaddr) -> bool {
    if is_onion_address(address) && !is_canonical_onion_address(address) {
        return false;
    }
    match mode {
        TorMode::DisableTor => !is_onion_address(address),
        TorMode::RequireTor => is_canonical_onion_address(address),
        TorMode::Auto | TorMode::PreferTor => true,
    }
}

fn transport_address_allowed(mode: TorMode, address: &Multiaddr) -> bool {
    address_allowed_by_tor_mode(mode, address)
}

fn transport_path_allowed(mode: TorMode, path: P2pPath) -> bool {
    match mode {
        TorMode::DisableTor => path != P2pPath::Tor,
        TorMode::RequireTor => path == P2pPath::Tor,
        TorMode::Auto | TorMode::PreferTor => true,
    }
}

fn path_preference_rank(mode: TorMode, path: P2pPath) -> u8 {
    match mode {
        TorMode::Auto => match path {
            P2pPath::Direct | P2pPath::HolePunched => 0,
            P2pPath::Relayed | P2pPath::RelayFallback => 1,
            P2pPath::Tor => 2,
        },
        TorMode::PreferTor => match path {
            P2pPath::Tor => 0,
            P2pPath::Direct | P2pPath::HolePunched => 1,
            P2pPath::Relayed | P2pPath::RelayFallback => 2,
        },
        TorMode::RequireTor => u8::from(path != P2pPath::Tor),
        TorMode::DisableTor => match path {
            P2pPath::Direct | P2pPath::HolePunched => 0,
            P2pPath::Relayed | P2pPath::RelayFallback => 1,
            P2pPath::Tor => 2,
        },
    }
}

fn should_retire_non_policy_connection(
    mode: TorMode,
    path: P2pPath,
    selected_tier: Option<u8>,
    selected_connection_exists: bool,
) -> bool {
    !transport_path_allowed(mode, path)
        || selected_connection_exists
            && selected_tier.is_some_and(|tier| path_preference_rank(mode, path) != tier)
}

fn address_path(address: &Multiaddr) -> P2pPath {
    if is_onion_address(address) {
        P2pPath::Tor
    } else if address
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2pCircuit))
    {
        P2pPath::Relayed
    } else {
        P2pPath::Direct
    }
}

fn policy_address_tiers(
    mode: TorMode,
    addresses: impl IntoIterator<Item = Multiaddr>,
) -> BTreeMap<u8, BTreeSet<Multiaddr>> {
    let mut tiers = BTreeMap::<u8, BTreeSet<Multiaddr>>::new();
    for address in addresses {
        if !address_allowed_by_tor_mode(mode, &address) {
            continue;
        }
        tiers
            .entry(path_preference_rank(mode, address_path(&address)))
            .or_default()
            .insert(address);
    }
    tiers
}

fn selected_policy_addresses(
    mode: TorMode,
    addresses: impl IntoIterator<Item = Multiaddr>,
    requested_tier: u8,
) -> (u8, BTreeSet<Multiaddr>) {
    let tiers = policy_address_tiers(mode, addresses);
    tiers
        .range(requested_tier..)
        .next()
        .or_else(|| tiers.first_key_value())
        .map(|(tier, addresses)| (*tier, addresses.clone()))
        .unwrap_or((0, BTreeSet::new()))
}

#[cfg(test)]
fn next_preferred_addresses(
    tiers: &BTreeMap<u8, BTreeSet<Multiaddr>>,
    current_tier: u8,
) -> Vec<Multiaddr> {
    tiers
        .range(..current_tier)
        .flat_map(|(_, addresses)| addresses.iter().cloned())
        .collect()
}

fn connected_point_path(endpoint: &ConnectedPoint) -> P2pPath {
    if endpoint.is_relayed() {
        return P2pPath::Relayed;
    }
    let address = match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { local_addr, .. } => local_addr,
    };
    if is_onion_address(address) {
        P2pPath::Tor
    } else {
        P2pPath::Direct
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PublishedTransportClass {
    Direct,
    Relay,
    Onion,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct AdvertisedEndpointSelection {
    addresses: Vec<String>,
    rejected: Vec<String>,
}

fn published_transport_class(address: &Multiaddr) -> PublishedTransportClass {
    if is_onion_address(address) {
        PublishedTransportClass::Onion
    } else if address
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2pCircuit))
    {
        PublishedTransportClass::Relay
    } else {
        PublishedTransportClass::Direct
    }
}

fn validate_local_publication_candidate(
    peer: PeerId,
    value: &str,
) -> Result<(String, PublishedTransportClass)> {
    let mut address: Multiaddr = value
        .parse()
        .with_context(|| format!("invalid advertised endpoint {value}"))?;
    if address.iter().last() != Some(libp2p::multiaddr::Protocol::P2p(peer)) {
        address.push(libp2p::multiaddr::Protocol::P2p(peer));
    }
    let mut address = validate_published_endpoint_for_peer(peer, &address.to_string())?;
    address.pop();
    let class = published_transport_class(&address);
    Ok((address.to_string(), class))
}

fn status_advertised_addresses(
    local_peer: PeerId,
    configured: &[Multiaddr],
    mapped: Option<&Multiaddr>,
    listen_addresses: &[String],
) -> AdvertisedEndpointSelection {
    let mut candidates = if configured.is_empty() {
        listen_addresses.to_vec()
    } else {
        let mut addresses = configured
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        addresses.extend(
            listen_addresses
                .iter()
                .filter(|value| {
                    value.contains("/p2p-circuit")
                        || value
                            .parse::<Multiaddr>()
                            .is_ok_and(|address| is_onion_address(&address))
                })
                .cloned(),
        );
        addresses
    };
    if let Some(mapped) = mapped {
        candidates.push(mapped.to_string());
    }
    candidates.sort();
    candidates.dedup();

    let mut valid = BTreeMap::<PublishedTransportClass, BTreeSet<String>>::new();
    let mut rejected = Vec::new();
    for candidate in candidates {
        match validate_local_publication_candidate(local_peer, &candidate) {
            Ok((address, class)) => {
                valid.entry(class).or_default().insert(address);
            }
            Err(error) => rejected.push(format!(
                "advertised endpoint candidate {candidate} was rejected: {error}"
            )),
        }
    }

    // Keep one deterministic address for every available transport class
    // before filling the remaining protocol slots. Onion comes first so an
    // enabled live fallback cannot be displaced by relay address expansion.
    let mut selected = BTreeSet::new();
    for class in [
        PublishedTransportClass::Onion,
        PublishedTransportClass::Relay,
        PublishedTransportClass::Direct,
    ] {
        if let Some(address) = valid.get(&class).and_then(|addresses| addresses.first()) {
            selected.insert(address.clone());
        }
    }
    for address in valid.into_values().flatten() {
        if selected.len() == MAX_ENDPOINTS_PER_PEER {
            break;
        }
        selected.insert(address);
    }
    rejected.sort();
    rejected.dedup();
    AdvertisedEndpointSelection {
        addresses: selected.into_iter().collect(),
        rejected,
    }
}

fn valid_advertised_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
}

fn valid_advertised_ipv6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_unicast_link_local()
}

/// Accept exactly the address shapes implemented by the composed transport.
/// The terminal local `/p2p` component is added and checked separately.
fn supported_advertised_transport(address: &Multiaddr) -> bool {
    if is_canonical_onion_address(address) {
        return true;
    }

    if supported_direct_quic_transport(address) {
        return true;
    }

    let mut protocols = address.iter();
    let ip_is_usable = match protocols.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(address)) => valid_advertised_ipv4(address),
        Some(libp2p::multiaddr::Protocol::Ip6(address)) => valid_advertised_ipv6(address),
        _ => false,
    };
    let port_is_usable = matches!(
        protocols.next(),
        Some(libp2p::multiaddr::Protocol::Udp(port)) if port != 0
    );
    if !ip_is_usable
        || !port_is_usable
        || !matches!(protocols.next(), Some(libp2p::multiaddr::Protocol::QuicV1))
    {
        return false;
    }
    matches!(protocols.next(), Some(libp2p::multiaddr::Protocol::P2p(_)))
        && matches!(
            protocols.next(),
            Some(libp2p::multiaddr::Protocol::P2pCircuit)
        )
        && protocols.next().is_none()
}

fn supported_direct_quic_transport(address: &Multiaddr) -> bool {
    let mut protocols = address.iter();
    let ip_is_usable = match protocols.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(address)) => valid_advertised_ipv4(address),
        Some(libp2p::multiaddr::Protocol::Ip6(address)) => valid_advertised_ipv6(address),
        _ => false,
    };
    ip_is_usable
        && matches!(
            protocols.next(),
            Some(libp2p::multiaddr::Protocol::Udp(port)) if port != 0
        )
        && matches!(protocols.next(), Some(libp2p::multiaddr::Protocol::QuicV1))
        && protocols.next().is_none()
}

fn validate_published_endpoint_for_peer(expected_peer: PeerId, value: &str) -> Result<Multiaddr> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
        bail!("advertised endpoint is empty or too long");
    }
    let mut address: Multiaddr = value
        .parse()
        .with_context(|| format!("invalid advertised endpoint {value}"))?;
    if address.iter().last() != Some(libp2p::multiaddr::Protocol::P2p(expected_peer)) {
        bail!("advertised endpoint is not bound to its seed-derived peer identity");
    }
    if !onion_address_matches_peer(&address, expected_peer) {
        bail!("advertised onion endpoint differs from its peer identity");
    }
    address.pop();
    if !supported_advertised_transport(&address) {
        bail!("advertised endpoint is not usable by the configured libp2p transports");
    }
    let canonical = address.with(libp2p::multiaddr::Protocol::P2p(expected_peer));
    if canonical.to_string() != value {
        bail!("advertised endpoint is not in canonical multiaddress form");
    }
    Ok(canonical)
}

/// Validate one exact peer-qualified value at the signed protocol boundary.
pub(crate) fn validate_published_endpoint(node_id: NodeId, value: &str) -> Result<Multiaddr> {
    validate_published_endpoint_for_peer(node_id.libp2p_peer_id()?, value)
}

/// Strictly validate configured entry points before any network runtime starts.
pub fn validate_bootstrap_addresses(mode: TorMode, values: &[String]) -> Result<Vec<Multiaddr>> {
    if values.len() > MAX_BOOTSTRAP_ADDRESSES {
        bail!(
            "configured {} bootstrap addresses; limit is {MAX_BOOTSTRAP_ADDRESSES}",
            values.len()
        );
    }
    let mut validated = BTreeSet::new();
    for value in values {
        if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
            bail!("bootstrap address is empty or too long");
        }
        let address: Multiaddr = value
            .parse()
            .with_context(|| format!("invalid bootstrap multiaddress {value}"))?;
        if address.to_string() != *value {
            bail!("bootstrap address is not in canonical multiaddress form: {value}");
        }
        let peer = terminal_peer_id(&address)
            .with_context(|| format!("bootstrap address has no destination peer ID: {value}"))?;
        validate_published_endpoint_for_peer(peer, value)
            .with_context(|| format!("invalid bootstrap address {value}"))?;
        if !address_allowed_by_tor_mode(mode, &address) {
            bail!("bootstrap address is incompatible with Tor mode {mode}: {value}");
        }
        validated.insert(address);
    }
    Ok(validated.into_iter().collect())
}

fn canonical_published_endpoint(node_id: NodeId, address: &Multiaddr) -> Result<String> {
    let endpoint = address
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node_id.libp2p_peer_id()?))
        .to_string();
    validate_published_endpoint(node_id, &endpoint)?;
    Ok(endpoint)
}

/// Validate one QUIC listener and return the longest peer-publishable address
/// it can produce. Wildcard listeners are valid bind points but are not
/// themselves dialable endpoints. Port zero is replaced by the longest valid
/// `u16` representation so the final protocol length check is conservative.
fn listener_publication_candidate(address: &Multiaddr) -> Result<Option<Multiaddr>> {
    let mut protocols = address.iter();
    let ip = match protocols.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(address))
            if !address.is_multicast() && !address.is_broadcast() =>
        {
            if address.is_unspecified() {
                None
            } else {
                Some(libp2p::multiaddr::Protocol::Ip4(address))
            }
        }
        Some(libp2p::multiaddr::Protocol::Ip6(address))
            if !address.is_multicast() && !address.is_unicast_link_local() =>
        {
            if address.is_unspecified() {
                None
            } else {
                Some(libp2p::multiaddr::Protocol::Ip6(address))
            }
        }
        _ => bail!("libp2p listener must start with a unicast IP address or wildcard"),
    };
    let port = match protocols.next() {
        Some(libp2p::multiaddr::Protocol::Udp(port)) => port,
        _ => bail!("libp2p listener must use UDP"),
    };
    if !matches!(protocols.next(), Some(libp2p::multiaddr::Protocol::QuicV1))
        || protocols.next().is_some()
    {
        bail!("libp2p listener must be an IP/UDP/QUIC-v1 address");
    }
    Ok(ip.map(|ip| {
        Multiaddr::empty()
            .with(ip)
            .with(libp2p::multiaddr::Protocol::Udp(if port == 0 {
                u16::MAX
            } else {
                port
            }))
            .with(libp2p::multiaddr::Protocol::QuicV1)
    }))
}

/// Validate every operator-asserted direct endpoint against the seed-derived
/// identity and strip a redundant terminal local peer ID. Onion and relay
/// circuit endpoints are derived only from their live runtime listeners.
pub fn validate_local_advertised_endpoints(
    node_id: NodeId,
    mode: TorMode,
    listen_addresses: &[Multiaddr],
    external_addresses: &[Multiaddr],
    relay_reservation_addresses: &[Multiaddr],
    enable_port_mapping: bool,
) -> Result<Vec<Multiaddr>> {
    let expected_peer = node_id.libp2p_peer_id()?;
    let mut canonical_external = BTreeSet::new();
    for configured in external_addresses {
        let mut address = configured.clone();
        if let Some(libp2p::multiaddr::Protocol::P2p(peer)) = address.iter().last() {
            if peer != expected_peer {
                bail!("advertised endpoint contains another peer identity");
            }
            address.pop();
        }
        if !supported_direct_quic_transport(&address) {
            bail!("configured external address must be a concrete IP/UDP/QUIC-v1 endpoint");
        }
        canonical_published_endpoint(node_id, &address)?;
        if mode.requires_tor() {
            bail!("configured external address is incompatible with require-tor mode");
        }
        canonical_external.insert(address);
    }
    if canonical_external.len() > MAX_ENDPOINTS_PER_PEER {
        bail!(
            "configured {} external addresses; protocol limit is {MAX_ENDPOINTS_PER_PEER}",
            canonical_external.len()
        );
    }

    let mut has_publishable_candidate = !canonical_external.is_empty();
    for listener in listen_addresses {
        let candidate = listener_publication_candidate(listener)?;
        if !mode.requires_tor() && canonical_external.is_empty() && candidate.is_some() {
            has_publishable_candidate = true;
        }
    }
    if relay_reservation_addresses.len() > MAX_ENDPOINTS_PER_PEER {
        bail!(
            "configured {} relay reservation addresses; limit is {MAX_ENDPOINTS_PER_PEER}",
            relay_reservation_addresses.len()
        );
    }
    for relay in relay_reservation_addresses {
        let relay_peer = terminal_peer_id(relay)?;
        if relay.iter().last() != Some(libp2p::multiaddr::Protocol::P2p(relay_peer)) {
            bail!("relay reservation address must end in its relay peer identity");
        }
        let candidate = relay.clone().with(libp2p::multiaddr::Protocol::P2pCircuit);
        canonical_published_endpoint(node_id, &candidate)?;
        if !mode.requires_tor() {
            has_publishable_candidate = true;
        }
    }
    if mode.enabled() {
        let onion = super::onion_listener_address(node_id)?;
        canonical_published_endpoint(node_id, &onion)?;
        has_publishable_candidate = true;
    }
    if enable_port_mapping {
        has_publishable_candidate = true;
    }
    if !has_publishable_candidate {
        bail!("local endpoint configuration has no publishable address");
    }
    Ok(canonical_external.into_iter().collect())
}

pub fn build_p2p(
    node: Arc<Mutex<Node>>,
    mut config: P2pConfig,
) -> Result<(P2pClient, P2pEventLoop)> {
    config.tor_mode = TorMode::DisableTor;
    build_p2p_with_tor(node, config, None)
}

pub fn build_p2p_with_tor(
    node: Arc<Mutex<Node>>,
    mut config: P2pConfig,
    tor_transport: Option<TorTransport>,
) -> Result<(P2pClient, P2pEventLoop)> {
    config.bootstrap_addresses = validate_bootstrap_addresses(
        config.tor_mode,
        &config
            .bootstrap_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )?;
    if config.enable_port_mapping {
        if config.tor_mode.requires_tor() {
            bail!("port mapping cannot be enabled in require-tor mode");
        }
        super::port_mapping::validate_port_mapping_listeners(&config.listen_addresses)?;
    }
    if config.listen_addresses.is_empty()
        && config.relay_reservation_addresses.is_empty()
        && tor_transport.is_none()
        || config.configure_failure_domain && config.failure_domain.is_empty()
        || config.max_connections == 0
        || config.tor_mode.enabled() != tor_transport.is_some()
    {
        bail!("invalid libp2p configuration");
    }
    let local_node_id = node
        .lock()
        .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?
        .keys()
        .node_id();
    config.external_addresses = validate_local_advertised_endpoints(
        local_node_id,
        config.tor_mode,
        &config.listen_addresses,
        &config.external_addresses,
        &config.relay_reservation_addresses,
        config.enable_port_mapping,
    )?;
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
    let tor_listen_address = tor_transport
        .as_ref()
        .map(|transport| transport.listen_address().clone());
    let optional_tor = match tor_transport {
        Some(transport) => OptionalTransport::some(transport),
        None => OptionalTransport::none(),
    };
    let quic_transport = quic::tokio::Transport::new(quic::Config::new(&identity))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
    let tor_transport = optional_tor
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&identity)?)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let relay_transport = relay_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&identity)?)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
    let transport = quic_transport
        .or_transport(tor_transport)
        .map(|either, _| either.into_inner())
        .or_transport(relay_transport)
        .map(|either, _| either.into_inner());
    let transport = PolicyTransport::new(transport, config.tor_mode);
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_other_transport(move |_| transport)?
        .with_behaviour(move |key| {
            let peer_id = key.public().to_peer_id();
            let mut kad_config = kad::Config::new(KAD_PROTOCOL);
            kad_config
                .set_query_timeout(Duration::from_secs(30))
                .set_replication_factor(
                    NonZeroUsize::new(DHT_REPLICATION_FACTOR)
                        .expect("DHT replication factor is nonzero"),
                )
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
                    request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
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
    let mut port_mapping_listener = None;
    for address in config
        .listen_addresses
        .iter()
        .filter(|_| !config.tor_mode.requires_tor())
    {
        let listener = swarm
            .listen_on(address.clone())
            .with_context(|| format!("cannot listen on {address}"))?;
        if config.enable_port_mapping
            && super::port_mapping::ipv4_quic_listener(address)
                .is_some_and(|(ip, _)| ip.is_unspecified())
        {
            port_mapping_listener = Some(listener);
        }
        direct_listeners.insert(listener, address.clone());
    }
    let tor_listener = match tor_listen_address {
        Some(address) => {
            let listener = swarm
                .listen_on(address.clone())
                .with_context(|| format!("cannot launch onion listener on {address}"))?;
            Some((listener, address))
        }
        None => None,
    };
    for address in &config.external_addresses {
        if !address_allowed_by_tor_mode(config.tor_mode, address) {
            continue;
        }
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
    let bootstrap_addresses = config.bootstrap_addresses.clone();
    let mut bootstrap_peers = BTreeSet::new();
    for address in &bootstrap_addresses {
        let peer = terminal_peer_id(address)?;
        let normalized = normalize_known_address(peer, address.clone())?;
        persistent_addresses
            .entry(peer)
            .or_default()
            .insert(normalized);
        bootstrap_peers.insert(peer);
    }
    let mut relay_reservations = Vec::new();
    let mut relay_reservation_peers = HashSet::new();
    let mut relay_listeners = HashMap::new();
    for address in config
        .relay_reservation_addresses
        .iter()
        .filter(|_| !config.tor_mode.requires_tor())
    {
        let peer = terminal_peer_id(address)?;
        let normalized = normalize_known_address(peer, address.clone())?;
        persistent_addresses
            .entry(peer)
            .or_default()
            .insert(normalized);
        relay_reservation_peers.insert(peer);
        let reservation = address
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        let listener = swarm
            .listen_on(reservation.clone())
            .with_context(|| format!("cannot request relay reservation through {reservation}"))?;
        relay_reservations.push(reservation.clone());
        relay_listeners.insert(listener, reservation);
    }
    let mut installed_policy_addresses = HashMap::new();
    let mut fallback_tiers = HashMap::new();
    let mut policy_dials = HashMap::new();
    for (peer, addresses) in &persistent_addresses {
        let (selected_tier, selected) =
            selected_policy_addresses(config.tor_mode, addresses.iter().cloned(), 0);
        if selected_tier > 0 {
            fallback_tiers.insert(*peer, selected_tier);
        }
        for address in &selected {
            swarm.add_peer_address(*peer, address.clone());
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer, address.clone());
        }
        if !selected.is_empty() {
            installed_policy_addresses.insert(*peer, selected);
        }
    }
    for peer in bootstrap_peers {
        let addresses = installed_policy_addresses
            .get(&peer)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            continue;
        }
        let dial = SwarmDialOpts::peer_id(peer)
            .addresses(addresses)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        let connection_id = dial.connection_id();
        let tier = installed_policy_addresses
            .get(&peer)
            .and_then(|addresses| addresses.iter().next())
            .map(|address| path_preference_rank(config.tor_mode, address_path(address)))
            .unwrap_or(0);
        let path = installed_policy_addresses
            .get(&peer)
            .and_then(|addresses| addresses.iter().next())
            .map(address_path)
            .unwrap_or(P2pPath::Direct);
        match swarm.dial(dial) {
            Ok(()) => {
                policy_dials.insert(
                    connection_id,
                    PolicyDial {
                        peer,
                        tier,
                        path,
                        kind: PolicyDialKind::Selected,
                    },
                );
            }
            Err(error) => {
                tracing::warn!(%peer, %error, "initial libp2p dial was rejected");
            }
        }
    }
    if config.enable_dht_maintenance
        && !bootstrap_addresses.is_empty()
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
    let (request_cancellation_sender, request_cancellations) = mpsc::unbounded_channel();
    let (inbound_sender, inbound_results) = mpsc::channel(COMMAND_CAPACITY);
    let (startup_sender, startup_receiver) = oneshot::channel();
    let (port_mapping_listener_sender, port_mapping_listener_receiver) =
        watch::channel(PortMappingListenerState::Pending);
    Ok((
        P2pClient {
            local_peer_id,
            commands: command_sender,
            request_cancellations: request_cancellation_sender,
            outbound_permits: Arc::new(Semaphore::new(config.max_connections)),
            cold_recovery_permit: Arc::new(Semaphore::new(1)),
            port_mapping_listener_state: port_mapping_listener_receiver,
        },
        P2pEventLoop {
            swarm,
            commands: command_receiver,
            request_cancellations,
            inbound_results,
            inbound_sender,
            inbound_permits: Arc::new(Semaphore::new(config.max_connections)),
            pending_requests: HashMap::new(),
            queued_requests: VecDeque::new(),
            active_inbound_requests: HashMap::new(),
            pending_response_bytes: HashMap::new(),
            pending_dht: HashMap::new(),
            service,
            server_config,
            advertised_addresses: config
                .external_addresses
                .into_iter()
                .filter(|address| address_allowed_by_tor_mode(config.tor_mode, address))
                .collect(),
            port_mapping_enabled: config.enable_port_mapping,
            mapped_external_address: None,
            port_mapping_listener,
            port_mapping_listener_active: false,
            port_mapping_listener_state: port_mapping_listener_sender,
            direct_listeners,
            active_direct_listeners: HashSet::new(),
            closed_direct_listeners: HashSet::new(),
            tor_mode: config.tor_mode,
            tor_listener,
            active_tor_listener: false,
            bootstrap_addresses,
            enable_dht_maintenance: config.enable_dht_maintenance,
            bootstrap_retry: retry_interval(BOOTSTRAP_RETRY_INTERVAL),
            relay_reservations,
            relay_reservation_peers,
            relay_listeners,
            active_relay_listeners: HashSet::new(),
            relay_retry: retry_interval(RELAY_RESERVATION_RETRY_INTERVAL),
            relay_retirement: HashMap::new(),
            relay_retirement_tick: retry_interval(RELAY_RETIREMENT_POLL_INTERVAL),
            relay_members,
            persistent_addresses,
            installed_policy_addresses,
            fallback_tiers,
            policy_dials,
            transport_promotions: HashMap::new(),
            preferred_path_retry: retry_interval(PREFERRED_PATH_RETRY_INTERVAL),
            request_maintenance: retry_interval(REQUEST_MAINTENANCE_INTERVAL),
            learned_addresses: HashMap::new(),
            opportunistic_addresses: HashMap::new(),
            recovery_addresses: HashMap::new(),
            recovery_quarantine: HashMap::new(),
            learned_endpoint_expiry: retry_interval(LEARNED_ENDPOINT_EXPIRY_INTERVAL),
            connection_paths: HashMap::new(),
            closed_connection_paths: HashMap::new(),
            connection_dialers: HashMap::new(),
            duplicate_retirement: HashMap::new(),
            next_session_sequence: 1,
            sessions: HashMap::new(),
            recent_sessions: VecDeque::new(),
            path_metrics: BTreeMap::new(),
            collapsing_connections: HashSet::new(),
            unhealthy_connections: HashSet::new(),
            last_application_paths: HashMap::new(),
            transfer_counters: HashMap::new(),
            path_transfer_counters: HashMap::new(),
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
            .send(Command::AddLearnedAddress {
                peer,
                address,
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver.await.context("libp2p address command was lost")?
    }

    async fn add_recovery_addresses(
        &self,
        scope: Uuid,
        peer: NodeId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
    ) -> Result<()> {
        let peer = peer.libp2p_peer_id()?;
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::AddRecoveryAddresses {
                scope,
                peer,
                addresses,
                expires_at_unix_seconds,
                response,
            })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p recovery-address command was lost")?
    }

    async fn clear_recovery_addresses(&self, scope: Uuid) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::ClearRecoveryAddresses { scope, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p recovery-address cleanup was lost")?
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

    pub(crate) async fn set_mapped_external_address(
        &self,
        address: Option<Multiaddr>,
    ) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::SetMappedExternalAddress { address, response })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p port-mapping command was lost")?
    }

    pub(super) fn port_mapping_listener_state(&self) -> watch::Receiver<PortMappingListenerState> {
        self.port_mapping_listener_state.clone()
    }

    #[cfg(test)]
    pub(crate) async fn close_port_mapping_listener(&self) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::ClosePortMappingListener { response })
            .await
            .context("libp2p event loop stopped")?;
        receiver
            .await
            .context("libp2p listener-close command was lost")?
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

    pub async fn exchange_endpoints(
        &self,
        peer: NodeId,
        guild_id: [u8; 32],
    ) -> Result<Vec<SignedRecord<mb_core::EndpointRecord>>> {
        let response = self
            .call(peer, PeerRequest::ExchangeEndpoints { guild_id })
            .await?;
        let PeerResponse::EndpointRecords(records) = response else {
            bail!("peer returned the wrong response to endpoint exchange");
        };
        if records.len() > MAX_EXCHANGED_ENDPOINT_RECORDS {
            bail!("peer returned too many endpoint records");
        }
        Ok(records)
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
        let permit = self
            .outbound_permits
            .clone()
            .acquire_owned()
            .await
            .context("libp2p event loop stopped")?;
        let (response, receiver) = oneshot::channel();
        let cancellation_id = Uuid::new_v4();
        let mut cancellation =
            RequestCancellation::new(cancellation_id, self.request_cancellations.clone());
        self.commands
            .send(Command::Request {
                cancellation_id,
                peer: expected_peer_id,
                recipient: peer,
                request: Box::new(request),
                response,
                permit,
            })
            .await
            .context("libp2p event loop stopped")?;
        let result = receiver.await.context("libp2p request command was lost");
        cancellation.disarm();
        result?
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

    fn application_path(&self, connection_id: ConnectionId) -> Option<P2pPath> {
        self.connection_paths
            .get(&connection_id)
            .map(|(_, path)| *path)
            .or_else(|| {
                self.closed_connection_paths
                    .get(&connection_id)
                    .map(|closed| closed.path)
            })
            .map(|path| match path {
                P2pPath::Relayed => P2pPath::RelayFallback,
                path => path,
            })
    }

    fn request_failure_path(&self, peer: PeerId, connection_id: ConnectionId) -> Option<P2pPath> {
        self.connection_paths
            .get(&connection_id)
            .filter(|(candidate, _)| *candidate == peer)
            .map(|(_, path)| *path)
            .or_else(|| {
                self.closed_connection_paths
                    .get(&connection_id)
                    .filter(|closed| closed.peer == peer)
                    .map(|closed| closed.path)
            })
            .map(|path| match path {
                P2pPath::Relayed => P2pPath::RelayFallback,
                path => path,
            })
    }

    fn remember_closed_connection_path(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        path: P2pPath,
    ) {
        if self.closed_connection_paths.len() >= MAX_SESSION_HISTORY
            && let Some(oldest) = self
                .closed_connection_paths
                .iter()
                .min_by_key(|(_, closed)| closed.expires_at)
                .map(|(connection, _)| *connection)
        {
            self.closed_connection_paths.remove(&oldest);
        }
        self.closed_connection_paths.insert(
            connection_id,
            ClosedConnectionPath {
                peer,
                path,
                expires_at: tokio::time::Instant::now() + CLOSED_CONNECTION_PATH_RETENTION,
            },
        );
    }

    fn retains_transfer_history(&self, peer: PeerId) -> bool {
        self.persistent_addresses.contains_key(&peer)
            || self.learned_addresses.contains_key(&peer)
            || self
                .recovery_addresses
                .values()
                .any(|scope| scope.addresses.contains_key(&peer))
            || self
                .relay_members
                .read()
                .is_ok_and(|members| members.contains(&peer))
    }

    fn forget_transfer_history_if_unretained(&mut self, peer: PeerId) {
        if self.retains_transfer_history(peer) {
            return;
        }
        self.transfer_counters.remove(&peer);
        self.path_transfer_counters.remove(&peer);
    }

    fn retains_transport_selection(&self, peer: PeerId) -> bool {
        !self.retained_peer_addresses(peer).is_empty()
            || self
                .connection_paths
                .values()
                .any(|(candidate, _)| *candidate == peer)
            || self.policy_dials.values().any(|dial| dial.peer == peer)
            || self.has_outstanding_request(peer)
            || self.transport_promotions.contains_key(&peer)
    }

    fn forget_transport_selection_if_unretained(&mut self, peer: PeerId) {
        if !self.retains_transport_selection(peer) {
            self.fallback_tiers.remove(&peer);
        }
    }

    fn record_transfer(&mut self, peer: PeerId, path: Option<P2pPath>, sent: u64, received: u64) {
        if let Some(path) = path {
            let metrics = self.path_metrics.entry(path).or_default();
            metrics.application_bytes_sent = metrics.application_bytes_sent.saturating_add(sent);
            metrics.application_bytes_received =
                metrics.application_bytes_received.saturating_add(received);
        }
        if !self.retains_transfer_history(peer) {
            return;
        }
        let total = self.transfer_counters.entry(peer).or_default();
        total.sent = total.sent.saturating_add(sent);
        total.received = total.received.saturating_add(received);
        if let Some(path) = path {
            let by_path = self
                .path_transfer_counters
                .entry(peer)
                .or_default()
                .entry(path)
                .or_default();
            by_path.sent = by_path.sent.saturating_add(sent);
            by_path.received = by_path.received.saturating_add(received);
        }
    }

    fn record_request_result(
        &mut self,
        path: Option<P2pPath>,
        started_at: tokio::time::Instant,
        succeeded: bool,
    ) {
        let Some(path) = path else {
            return;
        };
        let metrics = self.path_metrics.entry(path).or_default();
        if succeeded {
            metrics.requests_succeeded = metrics.requests_succeeded.saturating_add(1);
        } else {
            metrics.requests_failed = metrics.requests_failed.saturating_add(1);
        }
        metrics.request_latency_millis_total = metrics
            .request_latency_millis_total
            .saturating_add(u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX));
    }

    fn record_session_open(
        &mut self,
        connection: ConnectionId,
        peer: PeerId,
        path: P2pPath,
        direction: P2pSessionDirection,
    ) {
        let sequence = self.next_session_sequence;
        self.next_session_sequence = self.next_session_sequence.saturating_add(1);
        self.sessions.insert(
            connection,
            SessionRuntime {
                sequence,
                peer,
                path,
                direction,
                opened_at_unix_seconds: unix_seconds(),
                opened_at: tokio::time::Instant::now(),
            },
        );
        let metrics = self.path_metrics.entry(path).or_default();
        metrics.sessions_opened = metrics.sessions_opened.saturating_add(1);
    }

    fn update_session_path(&mut self, connection: ConnectionId, path: P2pPath) {
        let Some(session) = self.sessions.get_mut(&connection) else {
            return;
        };
        if session.path == path {
            return;
        }
        let previous = session.path;
        session.path = path;
        // DCUtR reports the more precise classification for a connection that
        // Swarm may already have announced as generic direct QUIC. Move that
        // single opening between buckets instead of counting two sessions.
        let previous_metrics = self.path_metrics.entry(previous).or_default();
        previous_metrics.sessions_opened = previous_metrics.sessions_opened.saturating_sub(1);
        let metrics = self.path_metrics.entry(path).or_default();
        metrics.sessions_opened = metrics.sessions_opened.saturating_add(1);
    }

    fn classify_dcutr_connection(&mut self, peer: PeerId, connection: ConnectionId) {
        self.connection_paths
            .insert(connection, (peer, P2pPath::HolePunched));
        self.update_session_path(connection, P2pPath::HolePunched);

        // A simultaneous QUIC punch can establish one connection in each
        // direction.  libp2p's DCUtR event identifies the locally initiated
        // connection, while duplicate collapse deterministically retains the
        // direction selected from the two Peer IDs.  When those directions
        // differ, carry the DCUtR provenance to the newest matching direct
        // connection so both ends attribute traffic on the retained connection
        // to the hole punch instead of reporting it as an unrelated direct dial.
        let local_prefers_dialer = self.swarm.local_peer_id() < &peer;
        if self.connection_dialers.get(&connection).copied() == Some(local_prefers_dialer) {
            return;
        }
        let counterpart = self
            .connection_paths
            .iter()
            .filter_map(|(candidate, (candidate_peer, path))| {
                (*candidate != connection
                    && *candidate_peer == peer
                    && *path == P2pPath::Direct
                    && self.connection_dialers.get(candidate).copied()
                        == Some(local_prefers_dialer))
                .then_some((
                    *candidate,
                    self.sessions
                        .get(candidate)
                        .map(|session| session.sequence)
                        .unwrap_or(0),
                ))
            })
            .max_by_key(|(_, sequence)| *sequence)
            .map(|(candidate, _)| candidate);
        if let Some(counterpart) = counterpart {
            self.connection_paths
                .insert(counterpart, (peer, P2pPath::HolePunched));
            self.update_session_path(counterpart, P2pPath::HolePunched);
        }
    }

    fn classify_failed_dcutr(&mut self, peer: PeerId) {
        let relayed_connections = self
            .connection_paths
            .iter()
            .filter_map(|(connection, (candidate, path))| {
                (*candidate == peer && *path == P2pPath::Relayed).then_some(*connection)
            })
            .collect::<Vec<_>>();
        for connection in relayed_connections {
            self.connection_paths
                .insert(connection, (peer, P2pPath::RelayFallback));
            self.update_session_path(connection, P2pPath::RelayFallback);
        }
    }

    fn record_session_close(&mut self, connection: ConnectionId, transport_error: bool) {
        let Some(session) = self.sessions.remove(&connection) else {
            return;
        };
        let outcome = if self.collapsing_connections.remove(&connection) {
            P2pSessionOutcome::Collapsed
        } else if transport_error {
            P2pSessionOutcome::TransportError
        } else {
            P2pSessionOutcome::Closed
        };
        let duration_millis =
            u64::try_from(session.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let closed_at_unix_seconds = unix_seconds();
        self.recent_sessions.push_back(P2pSessionHistory {
            sequence: session.sequence,
            peer_id: session.peer.to_string(),
            path: session.path,
            direction: session.direction,
            opened_at_unix_seconds: session.opened_at_unix_seconds,
            closed_at_unix_seconds,
            duration_millis,
            outcome,
        });
        while self.recent_sessions.len() > MAX_SESSION_HISTORY {
            self.recent_sessions.pop_front();
        }
        let metrics = self.path_metrics.entry(session.path).or_default();
        metrics.sessions_closed = metrics.sessions_closed.saturating_add(1);
    }

    fn has_outstanding_request(&self, peer: PeerId) -> bool {
        self.pending_requests
            .values()
            .chain(self.queued_requests.iter())
            .any(|pending| pending.peer == peer)
    }

    fn connection_is_retiring_or_unhealthy(&self, connection: ConnectionId) -> bool {
        self.unhealthy_connections.contains(&connection)
            || self.collapsing_connections.contains(&connection)
            || self.relay_retirement.contains_key(&connection)
            || self.duplicate_retirement.contains_key(&connection)
    }

    fn peer_has_unsettled_connections(&self, peer: PeerId) -> bool {
        self.transport_promotions.contains_key(&peer)
            || self
                .connection_paths
                .iter()
                .any(|(connection, (candidate, _))| {
                    *candidate == peer && self.connection_is_retiring_or_unhealthy(*connection)
                })
    }

    fn healthy_connection_at_tier(
        &self,
        peer: PeerId,
        tier: u8,
        excluded: Option<ConnectionId>,
    ) -> bool {
        self.connection_paths
            .iter()
            .any(|(connection, (candidate, path))| {
                *candidate == peer
                    && excluded != Some(*connection)
                    && !self.connection_is_retiring_or_unhealthy(*connection)
                    && path_preference_rank(self.tor_mode, *path) == tier
            })
    }

    fn best_healthy_connection_tier(&self, peer: PeerId) -> Option<u8> {
        self.connection_paths
            .iter()
            .filter_map(|(connection, (candidate, path))| {
                (*candidate == peer && !self.connection_is_retiring_or_unhealthy(*connection))
                    .then_some(path_preference_rank(self.tor_mode, *path))
            })
            .min()
    }

    fn healthy_path_exists(&self, peer: PeerId, expected_path: P2pPath) -> bool {
        self.connection_paths
            .iter()
            .any(|(connection, (candidate, path))| {
                *candidate == peer
                    && *path == expected_path
                    && !self.connection_is_retiring_or_unhealthy(*connection)
            })
    }

    fn healthy_replacement_exists(
        &self,
        peer: PeerId,
        retiring: ConnectionId,
        maximum_rank: u8,
    ) -> bool {
        self.connection_paths
            .iter()
            .any(|(connection, (candidate, path))| {
                *connection != retiring
                    && *candidate == peer
                    && !self.connection_is_retiring_or_unhealthy(*connection)
                    && path_preference_rank(self.tor_mode, *path) <= maximum_rank
            })
    }

    fn selected_transport_tier(&self, peer: PeerId) -> u8 {
        self.fallback_tiers.get(&peer).copied().unwrap_or(0)
    }

    fn set_transport_tier(&mut self, peer: PeerId, tier: u8) {
        let previous = self.selected_transport_tier(peer);
        if tier == 0 {
            self.fallback_tiers.remove(&peer);
        } else {
            self.fallback_tiers.insert(peer, tier);
        }
        if previous != tier {
            tracing::info!(%peer, mode = %self.tor_mode, previous, tier, "changed peer transport tier");
        }
        self.reconcile_policy_addresses(peer);
    }

    fn retire_non_policy_connections(&mut self, peer: PeerId) {
        let selected_tier = self.selected_transport_tier(peer);
        let promotion_tier = self
            .transport_promotions
            .get(&peer)
            .map(|promotion| promotion.tier);
        let selected_connection_exists = self.healthy_connection_at_tier(peer, selected_tier, None);
        let connections = self
            .connection_paths
            .iter()
            .filter_map(|(connection, (candidate, path))| {
                if *candidate != peer || self.connection_is_retiring_or_unhealthy(*connection) {
                    return None;
                }
                // Address preference governs our outbound attempts.  A peer
                // may legitimately reach us over a fallback while every
                // preferred address we know for it is stale or unreachable.
                // Retire that established fallback only after a healthy
                // preferred-tier replacement actually exists; otherwise both
                // sides can enter a close/redial loop without ever carrying
                // an application request.
                let tier = path_preference_rank(self.tor_mode, *path);
                (promotion_tier != Some(tier)
                    && should_retire_non_policy_connection(
                        self.tor_mode,
                        *path,
                        Some(selected_tier),
                        selected_connection_exists,
                    ))
                .then_some(*connection)
            })
            .collect::<Vec<_>>();
        for connection in connections {
            self.duplicate_retirement.entry(connection).or_insert((
                peer,
                tokio::time::Instant::now() + TRANSPORT_PROMOTION_GRACE,
            ));
        }
    }

    fn dispatch_request(&mut self, mut pending: PendingRequest) {
        if !pending.caller_waiting() {
            return;
        }
        if pending.deadline <= tokio::time::Instant::now() {
            pending.finish(Err(anyhow::anyhow!("libp2p request deadline expired")));
            return;
        }
        if pending.attempts >= MAX_REQUEST_TRANSPORT_ATTEMPTS {
            pending.finish(Err(anyhow::anyhow!(
                "libp2p request exhausted its transport attempt budget"
            )));
            return;
        }
        pending.transport_tier = self.selected_transport_tier(pending.peer);
        pending.attempts = pending.attempts.saturating_add(1);
        pending.started_at = tokio::time::Instant::now();
        let outbound_id = self
            .swarm
            .behaviour_mut()
            .peer
            .send_request(&pending.peer, pending.request.clone());
        self.pending_requests.insert(outbound_id, pending);
    }

    fn queue_or_dispatch_request(&mut self, mut pending: PendingRequest) {
        if !pending.caller_waiting() {
            return;
        }
        if pending.deadline <= tokio::time::Instant::now() {
            pending.finish(Err(anyhow::anyhow!("libp2p request deadline expired")));
            return;
        }
        if pending.attempts >= MAX_REQUEST_TRANSPORT_ATTEMPTS {
            pending.finish(Err(anyhow::anyhow!(
                "libp2p request exhausted its transport attempt budget"
            )));
            return;
        }
        let peer = pending.peer;
        self.reconcile_policy_addresses(peer);
        let selected_tier = self.selected_transport_tier(peer);
        let selected_connection_exists = self.healthy_connection_at_tier(peer, selected_tier, None);
        if selected_connection_exists {
            self.retire_non_policy_connections(peer);
        } else {
            self.ensure_selected_transport(peer);
        }
        if !selected_connection_exists || self.peer_has_unsettled_connections(peer) {
            self.queued_requests.push_back(pending);
        } else {
            self.dispatch_request(pending);
        }
    }

    fn drain_queued_requests(&mut self, peer: PeerId) {
        let queued = self.queued_requests.len();
        for _ in 0..queued {
            let Some(pending) = self.queued_requests.pop_front() else {
                break;
            };
            if pending.peer == peer {
                self.queue_or_dispatch_request(pending);
            } else {
                self.queued_requests.push_back(pending);
            }
        }
    }

    fn cancel_request(&mut self, cancellation_id: Uuid) {
        if let Some(position) = self
            .queued_requests
            .iter()
            .position(|pending| pending.cancellation_id == cancellation_id)
        {
            if let Some(pending) = self.queued_requests.remove(position) {
                self.forget_transport_selection_if_unretained(pending.peer);
            }
            return;
        }
        if let Some(pending) = self
            .pending_requests
            .values_mut()
            .find(|pending| pending.cancellation_id == cancellation_id)
        {
            pending.response.take();
        }
        // libp2p request-response has no cancellation primitive. Keep a
        // dispatched request and its permit until its terminal event so a
        // caller cannot evade the configured in-flight bound by dropping its
        // response future. Removing the response sender suppresses retries.
    }

    fn maintain_requests(&mut self) {
        let now = tokio::time::Instant::now();
        let mut released_peers = BTreeSet::new();
        let queued = self.queued_requests.len();
        for _ in 0..queued {
            let Some(mut pending) = self.queued_requests.pop_front() else {
                break;
            };
            if !pending.caller_waiting() {
                released_peers.insert(pending.peer);
                continue;
            }
            if pending.deadline <= now {
                released_peers.insert(pending.peer);
                pending.finish(Err(anyhow::anyhow!("libp2p request deadline expired")));
            } else {
                self.queued_requests.push_back(pending);
            }
        }
        for pending in self.pending_requests.values_mut() {
            if pending.deadline <= now && pending.caller_waiting() {
                pending.finish(Err(anyhow::anyhow!("libp2p request deadline expired")));
            }
        }
        self.closed_connection_paths
            .retain(|_, closed| closed.expires_at > now);

        let peers = self
            .queued_requests
            .iter()
            .map(|pending| pending.peer)
            .collect::<BTreeSet<_>>();
        for peer in peers {
            self.drain_queued_requests(peer);
        }
        for peer in released_peers {
            self.forget_transport_selection_if_unretained(peer);
        }
    }

    async fn run_inner(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(command) = self.commands.recv() => {
                    if self.handle_command(command)? {
                        return Ok(());
                    }
                }
                Some(cancellation_id) = self.request_cancellations.recv() => {
                    self.cancel_request(cancellation_id);
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
                                    (result.peer, result.path, response_bytes),
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
                _ = self.relay_retirement_tick.tick(), if !self.relay_retirement.is_empty() || !self.duplicate_retirement.is_empty() || !self.transport_promotions.is_empty() => {
                    self.process_transport_promotions();
                    self.retire_idle_relay_connections();
                    self.retire_duplicate_sessions();
                }
                _ = self.preferred_path_retry.tick(), if !self.fallback_tiers.is_empty() || !self.connection_paths.is_empty() => {
                    self.retry_preferred_paths();
                }
                _ = self.learned_endpoint_expiry.tick(), if !self.learned_addresses.is_empty() || !self.opportunistic_addresses.is_empty() || !self.recovery_addresses.is_empty() || !self.recovery_quarantine.is_empty() => {
                    self.expire_learned_addresses();
                    self.expire_opportunistic_addresses();
                    self.expire_recovery_addresses();
                }
                _ = self.request_maintenance.tick(), if !self.queued_requests.is_empty() || !self.pending_requests.is_empty() || !self.closed_connection_paths.is_empty() => {
                    self.maintain_requests();
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
        if self.tor_mode.requires_tor() {
            self.active_tor_listener
        } else {
            !self.active_direct_listeners.is_empty()
                || !self.active_relay_listeners.is_empty()
                || self.active_tor_listener
        }
    }

    fn current_advertised_endpoints(&self) -> AdvertisedEndpointSelection {
        let listen_addresses = self
            .swarm
            .listeners()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        status_advertised_addresses(
            *self.swarm.local_peer_id(),
            &self.advertised_addresses,
            self.mapped_external_address.as_ref(),
            &listen_addresses,
        )
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
        if self.tor_mode.enabled() && !self.active_tor_listener {
            degraded.push("Tor onion service is not reachable".to_owned());
        }
        if self.port_mapping_enabled && self.mapped_external_address.is_none() {
            degraded.push("automatic gateway port mapping is not active".to_owned());
        }
        degraded.extend(self.current_advertised_endpoints().rejected);
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
                onion_service_reachable: self.active_tor_listener,
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
        let peers = self
            .bootstrap_addresses
            .iter()
            .filter_map(|address| terminal_peer_id(address).ok())
            .collect::<BTreeSet<_>>();
        for peer in peers {
            // A circuit address contains both the relay and destination peer
            // IDs. Connectivity to the relay does not mean the destination is
            // connected, so retries must key off the terminal identity.
            self.ensure_selected_transport(peer);
        }
        if self.enable_dht_maintenance
            && let Err(error) = self.swarm.behaviour_mut().kademlia.bootstrap()
        {
            tracing::debug!(%error, "Kademlia bootstrap retry could not start");
        }
    }

    fn retained_peer_addresses(&self, peer: PeerId) -> BTreeSet<Multiaddr> {
        let mut addresses = BTreeSet::new();
        if let Some(persistent) = self.persistent_addresses.get(&peer) {
            addresses.extend(persistent.iter().cloned());
        }
        if let Some(learned) = self.learned_addresses.get(&peer) {
            addresses.extend(learned.addresses.iter().cloned());
        }
        for scope in self.recovery_addresses.values() {
            if let Some(recovery) = scope.addresses.get(&peer) {
                addresses.extend(recovery.iter().cloned());
            }
        }
        addresses
    }

    fn reconcile_policy_addresses(&mut self, peer: PeerId) {
        let retained = self.retained_peer_addresses(peer);
        let tiers = policy_address_tiers(self.tor_mode, retained);
        let requested_tier = self.selected_transport_tier(peer);
        let requested_is_available = tiers.contains_key(&requested_tier)
            || self.healthy_connection_at_tier(peer, requested_tier, None)
            || self.policy_dial_exists(peer, requested_tier);
        let selected_tier = if requested_is_available {
            requested_tier
        } else {
            tiers
                .range(requested_tier..)
                .next()
                .or_else(|| tiers.first_key_value())
                .map(|(tier, _)| *tier)
                .or_else(|| self.best_healthy_connection_tier(peer))
                .unwrap_or(requested_tier)
        };
        let desired = tiers.get(&selected_tier).cloned().unwrap_or_default();
        if selected_tier == 0 {
            self.fallback_tiers.remove(&peer);
        } else {
            self.fallback_tiers.insert(peer, selected_tier);
        }
        let previous = self
            .installed_policy_addresses
            .remove(&peer)
            .unwrap_or_default();
        for address in previous.difference(&desired) {
            remove_known_address(&mut self.swarm, peer, address);
        }
        for address in desired.difference(&previous) {
            self.swarm.add_peer_address(peer, address.clone());
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer, address.clone());
        }
        if !desired.is_empty() {
            self.installed_policy_addresses.insert(peer, desired);
        }
        self.forget_transport_selection_if_unretained(peer);
    }

    fn replace_mapped_external_address(&mut self, address: Option<Multiaddr>) -> Result<()> {
        if address == self.mapped_external_address {
            return Ok(());
        }
        if address.is_some() && self.port_mapping_enabled && !self.port_mapping_listener_active {
            bail!("cannot publish a gateway mapping for an inactive QUIC listener");
        }
        if let Some(address) = &address
            && !super::port_mapping::valid_mapped_external_address(address)
        {
            bail!("port mapper returned an invalid external QUIC address");
        }
        if let Some(previous) = self.mapped_external_address.take() {
            self.swarm.remove_external_address(&previous);
        }
        if let Some(address) = address {
            self.swarm
                .behaviour_mut()
                .on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                    NewExternalAddrCandidate { addr: &address },
                ));
            self.swarm.add_external_address(address.clone());
            self.mapped_external_address = Some(address);
        }
        Ok(())
    }

    fn observe_port_mapping_listener_closed(&mut self, listener: ListenerId) {
        if self.port_mapping_listener != Some(listener) {
            return;
        }
        self.port_mapping_listener_active = false;
        if let Err(error) = self.replace_mapped_external_address(None) {
            self.fatal_error = Some(format!(
                "failed to withdraw gateway mapping after listener closure: {error}"
            ));
        }
        // The mapper begins acknowledged gateway deletion only after the
        // signed/runtime endpoint has been withdrawn above.
        self.port_mapping_listener_state
            .send_replace(PortMappingListenerState::Closed);
    }

    fn policy_dial_exists(&self, peer: PeerId, tier: u8) -> bool {
        self.policy_dials
            .values()
            .any(|dial| dial.peer == peer && dial.tier == tier)
    }

    fn start_policy_dial(
        &mut self,
        peer: PeerId,
        tier: u8,
        addresses: Vec<Multiaddr>,
        kind: PolicyDialKind,
    ) -> bool {
        if addresses.is_empty() || self.policy_dial_exists(peer, tier) {
            return false;
        }
        let path = address_path(&addresses[0]);
        debug_assert!(
            addresses
                .iter()
                .all(|address| path_preference_rank(self.tor_mode, address_path(address)) == tier)
        );
        let dial = SwarmDialOpts::peer_id(peer)
            .addresses(addresses)
            // Policy dials must not be suppressed by a retained fallback or
            // an unrelated behaviour-originated dial. The map above bounds us
            // to one explicit dial per peer/tier.
            .condition(PeerCondition::Always)
            .build();
        let connection_id = dial.connection_id();
        match self.swarm.dial(dial) {
            Ok(()) => {
                self.policy_dials.insert(
                    connection_id,
                    PolicyDial {
                        peer,
                        tier,
                        path,
                        kind,
                    },
                );
                true
            }
            Err(error) => {
                tracing::debug!(%peer, tier, %error, "policy-selected libp2p dial was rejected");
                false
            }
        }
    }

    fn ensure_selected_transport(&mut self, peer: PeerId) {
        let tier = self.selected_transport_tier(peer);
        if self.healthy_connection_at_tier(peer, tier, None) || self.policy_dial_exists(peer, tier)
        {
            return;
        }
        let addresses = self
            .installed_policy_addresses
            .get(&peer)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        self.start_policy_dial(peer, tier, addresses, PolicyDialKind::Selected);
    }

    fn selected_path_hint(&self, peer: PeerId) -> Option<P2pPath> {
        let address = self.installed_policy_addresses.get(&peer)?.iter().next()?;
        Some(address_path(address))
    }

    fn record_dial_failure(&mut self, peer: PeerId) {
        if let Some(path) = self.selected_path_hint(peer) {
            self.record_dial_failure_path(path);
        }
    }

    fn record_dial_failure_path(&mut self, path: P2pPath) {
        let metrics = self.path_metrics.entry(path).or_default();
        metrics.dial_failures = metrics.dial_failures.saturating_add(1);
    }

    fn activate_fallback(&mut self, peer: PeerId) -> bool {
        let current = self.selected_transport_tier(peer);
        let mut tiers = policy_address_tiers(self.tor_mode, self.retained_peer_addresses(peer))
            .into_keys()
            .collect::<BTreeSet<_>>();
        tiers.extend(
            self.connection_paths
                .iter()
                .filter_map(|(connection, (candidate, path))| {
                    (*candidate == peer && !self.connection_is_retiring_or_unhealthy(*connection))
                        .then_some(path_preference_rank(self.tor_mode, *path))
                }),
        );
        let Some(next) = tiers.into_iter().find(|tier| *tier > current) else {
            return false;
        };
        self.transport_promotions.remove(&peer);
        self.set_transport_tier(peer, next);
        if self.healthy_connection_at_tier(peer, next, None) {
            self.retire_non_policy_connections(peer);
        } else {
            self.ensure_selected_transport(peer);
        }
        true
    }

    fn retry_preferred_paths(&mut self) {
        let peers = self
            .fallback_tiers
            .keys()
            .copied()
            .chain(self.connection_paths.values().map(|(peer, _)| *peer))
            .collect::<BTreeSet<_>>();
        for peer in peers {
            let current_tier = self.selected_transport_tier(peer);
            if !self.healthy_connection_at_tier(peer, current_tier, None) {
                self.ensure_selected_transport(peer);
            }
            let tiers = policy_address_tiers(self.tor_mode, self.retained_peer_addresses(peer));
            for (tier, addresses) in tiers.range(..current_tier) {
                if self.healthy_connection_at_tier(peer, *tier, None) {
                    self.schedule_transport_promotion(peer, *tier);
                } else {
                    self.start_policy_dial(
                        peer,
                        *tier,
                        addresses.iter().cloned().collect(),
                        PolicyDialKind::PreferredProbe,
                    );
                }
            }
        }
    }

    fn schedule_transport_promotion(&mut self, peer: PeerId, tier: u8) {
        if tier >= self.selected_transport_tier(peer) {
            return;
        }
        let promotion = TransportPromotion {
            tier,
            deadline: tokio::time::Instant::now() + TRANSPORT_PROMOTION_GRACE,
        };
        match self.transport_promotions.entry(peer) {
            std::collections::hash_map::Entry::Occupied(mut entry) if tier < entry.get().tier => {
                entry.insert(promotion);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(promotion);
            }
            _ => {}
        }
    }

    fn process_transport_promotions(&mut self) {
        let now = tokio::time::Instant::now();
        let ready = self
            .transport_promotions
            .iter()
            .filter_map(|(peer, promotion)| {
                (promotion.deadline <= now).then_some((*peer, promotion.tier))
            })
            .collect::<Vec<_>>();
        for (peer, tier) in ready {
            self.transport_promotions.remove(&peer);
            if self.healthy_connection_at_tier(peer, tier, None) {
                self.set_transport_tier(peer, tier);
                self.retire_non_policy_connections(peer);
            }
            self.drain_queued_requests(peer);
            self.forget_transport_selection_if_unretained(peer);
        }
    }

    fn observe_established_transport(&mut self, peer: PeerId, connection: ConnectionId) {
        self.reconcile_policy_addresses(peer);
        let Some((_, path)) = self.connection_paths.get(&connection) else {
            return;
        };
        let tier = path_preference_rank(self.tor_mode, *path);
        let selected = self.selected_transport_tier(peer);
        if tier < selected {
            self.schedule_transport_promotion(peer, tier);
        } else if tier > selected {
            self.ensure_selected_transport(peer);
        }
        self.retire_non_policy_connections(peer);
    }

    fn restore_selected_transport_after_close(
        &mut self,
        peer: PeerId,
        closed_path: Option<P2pPath>,
    ) {
        let selected = self.selected_transport_tier(peer);
        if self.healthy_connection_at_tier(peer, selected, None) {
            return;
        }

        // A retirement marker means "close once a replacement remains
        // healthy". If that replacement disappeared before close began, the
        // retained connection becomes eligible again.
        self.duplicate_retirement
            .retain(|connection, (candidate, _)| {
                *candidate != peer || self.collapsing_connections.contains(connection)
            });
        if !self.healthy_path_exists(peer, P2pPath::HolePunched) {
            self.relay_retirement
                .retain(|_, (candidate, _)| *candidate != peer);
        }

        // A preferred probe may already have produced a usable connection
        // when the selected fallback disappears. There is no older selected
        // session left to protect with the promotion grace, so adopt the best
        // healthy established tier instead of redialing a worse endpoint and
        // leaving requests queued behind it.
        if let Some(best) = self.best_healthy_connection_tier(peer)
            && best <= selected
        {
            if best < selected {
                self.transport_promotions.remove(&peer);
                self.set_transport_tier(peer, best);
            }
            self.retire_non_policy_connections(peer);
            return;
        }

        if closed_path.is_some_and(|path| path_preference_rank(self.tor_mode, path) == selected)
            && self.activate_fallback(peer)
        {
            return;
        }
        self.reconcile_policy_addresses(peer);
        self.ensure_selected_transport(peer);
    }

    fn fail_queued_requests(&mut self, peer: PeerId, message: &str) {
        let queued = self.queued_requests.len();
        for _ in 0..queued {
            let Some(mut pending) = self.queued_requests.pop_front() else {
                break;
            };
            if pending.peer == peer {
                pending.finish(Err(anyhow::anyhow!(message.to_owned())));
            } else {
                self.queued_requests.push_back(pending);
            }
        }
        self.forget_transport_selection_if_unretained(peer);
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
            let address = normalize_known_address(peer, address)?;
            if address_allowed_by_tor_mode(self.tor_mode, &address) {
                normalized.insert(address);
            }
        }
        self.learned_addresses.remove(&peer);
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
        self.reconcile_policy_addresses(peer);
        self.forget_transfer_history_if_unretained(peer);
        Ok(())
    }

    fn add_learned_address(&mut self, peer: PeerId, address: Multiaddr) -> Result<()> {
        let address = normalize_known_address(peer, address)?;
        if !address_allowed_by_tor_mode(self.tor_mode, &address) {
            return Ok(());
        }
        let existing = self.learned_addresses.get(&peer);
        if existing.is_none() && self.learned_addresses.len() >= MAX_LEARNED_ENDPOINT_PEERS {
            bail!("learned endpoint cache is full");
        }
        if existing.is_some_and(|known| {
            !known.addresses.contains(&address) && known.addresses.len() >= MAX_ENDPOINTS_PER_PEER
        }) {
            bail!("peer has too many learned endpoints");
        }
        let learned = self
            .learned_addresses
            .entry(peer)
            .or_insert_with(|| LearnedAddresses {
                addresses: BTreeSet::new(),
                expires_at: tokio::time::Instant::now() + DHT_TTL,
            });
        learned.addresses.insert(address);
        learned.expires_at = tokio::time::Instant::now() + DHT_TTL;
        self.reconcile_policy_addresses(peer);
        Ok(())
    }

    fn remove_opportunistic_addresses(&mut self, peer: PeerId) {
        let Some(removed) = self.opportunistic_addresses.remove(&peer) else {
            return;
        };
        let retained = self
            .installed_policy_addresses
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        for address in removed.addresses.difference(&retained) {
            self.swarm
                .behaviour_mut()
                .kademlia
                .remove_address(&peer, address);
        }
    }

    fn add_opportunistic_address(&mut self, peer: PeerId, address: Multiaddr) {
        if !self.opportunistic_addresses.contains_key(&peer)
            && self.opportunistic_addresses.len() >= MAX_OPPORTUNISTIC_ENDPOINT_PEERS
            && let Some(evicted) = self
                .opportunistic_addresses
                .iter()
                .min_by_key(|(_, addresses)| addresses.expires_at)
                .map(|(peer, _)| *peer)
        {
            self.remove_opportunistic_addresses(evicted);
        }
        let addresses =
            self.opportunistic_addresses
                .entry(peer)
                .or_insert_with(|| LearnedAddresses {
                    addresses: BTreeSet::new(),
                    expires_at: tokio::time::Instant::now() + DHT_TTL,
                });
        if !addresses.addresses.contains(&address)
            && addresses.addresses.len() >= MAX_ENDPOINTS_PER_PEER
        {
            return;
        }
        addresses.addresses.insert(address.clone());
        addresses.expires_at = tokio::time::Instant::now() + DHT_TTL;
        // Keep these hints private to Kademlia. They let an authenticated DHT
        // neighbour route provider and record traffic without granting that
        // unknown peer a durable application-dial slot.
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer, address);
    }

    fn add_identified_address(&mut self, peer: PeerId, address: Multiaddr) -> Result<()> {
        let address = normalize_known_address(peer, address)?;
        if !address_allowed_by_tor_mode(self.tor_mode, &address) {
            return Ok(());
        }
        if address.to_string().len() > MAX_ENDPOINT_BYTES
            || address
                .iter()
                .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2p(_)))
        {
            bail!("Identify supplied an invalid peer address");
        }
        let authorized = self.persistent_addresses.contains_key(&peer)
            || self
                .relay_members
                .read()
                .is_ok_and(|members| members.contains(&peer));
        if authorized {
            self.remove_opportunistic_addresses(peer);
            return self.add_learned_address(peer, address);
        }

        let scopes = self
            .recovery_addresses
            .iter()
            .filter_map(|(scope_id, scope)| {
                scope.addresses.contains_key(&peer).then_some(*scope_id)
            })
            .collect::<Vec<_>>();
        if scopes.is_empty() {
            if self.recovery_quarantine.contains_key(&peer) {
                return Ok(());
            }
            // An authenticated libp2p session proves control of this Peer ID,
            // not guild membership or authority to consume the durable
            // endpoint cache. Retain a separately bounded, expendable
            // Kademlia-only hint so ordinary DHT routing still works.
            self.add_opportunistic_address(peer, address);
            return Ok(());
        }
        for scope_id in &scopes {
            let addresses = self
                .recovery_addresses
                .get(scope_id)
                .and_then(|scope| scope.addresses.get(&peer))
                .context("recovery address scope changed during Identify handling")?;
            if !addresses.contains(&address) && addresses.len() >= MAX_ENDPOINTS_PER_PEER {
                bail!("Identify supplied too many attempt-scoped recovery endpoints");
            }
        }
        self.remove_opportunistic_addresses(peer);
        for scope_id in scopes {
            self.recovery_addresses
                .get_mut(&scope_id)
                .and_then(|scope| scope.addresses.get_mut(&peer))
                .context("recovery address scope changed during Identify handling")?
                .insert(address.clone());
        }
        self.reconcile_policy_addresses(peer);
        Ok(())
    }

    fn add_recovery_addresses(
        &mut self,
        scope_id: Uuid,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        expires_at_unix_seconds: u64,
    ) -> Result<()> {
        let now_unix = unix_seconds();
        if addresses.is_empty()
            || addresses.len() > MAX_ENDPOINTS_PER_PEER
            || expires_at_unix_seconds <= now_unix
        {
            bail!("invalid attempt-scoped recovery endpoints");
        }
        if !self.recovery_addresses.contains_key(&scope_id)
            && self.recovery_addresses.len() >= MAX_RECOVERY_ADDRESS_SCOPES
        {
            bail!("too many recovery endpoint scopes");
        }
        let scope = self
            .recovery_addresses
            .entry(scope_id)
            .or_insert_with(|| RecoveryAddresses {
                addresses: HashMap::new(),
                expires_at: tokio::time::Instant::now() + DHT_TTL,
            });
        if !scope.addresses.contains_key(&peer)
            && scope.addresses.len() >= MAX_RECOVERY_ADDRESS_PEERS
        {
            bail!("recovery endpoint scope has too many peers");
        }
        let lifetime = Duration::from_secs(
            expires_at_unix_seconds
                .saturating_sub(now_unix)
                .min(DHT_TTL.as_secs()),
        );
        let expires_at = tokio::time::Instant::now() + lifetime;
        if !self.recovery_quarantine.contains_key(&peer)
            && self.recovery_quarantine.len() >= MAX_RECOVERY_QUARANTINED_PEERS
        {
            bail!("too many quarantined recovery peers");
        }
        self.recovery_quarantine
            .entry(peer)
            .and_modify(|current| *current = (*current).max(expires_at))
            .or_insert(expires_at);
        scope.expires_at = scope.expires_at.min(expires_at);
        let peer_addresses = scope.addresses.entry(peer).or_default();
        for address in addresses {
            let address = normalize_known_address(peer, address)?;
            if !address_allowed_by_tor_mode(self.tor_mode, &address) {
                continue;
            }
            if !peer_addresses.contains(&address) && peer_addresses.len() >= MAX_ENDPOINTS_PER_PEER
            {
                bail!("recovery peer has too many attempt-scoped endpoints");
            }
            peer_addresses.insert(address);
        }
        self.reconcile_policy_addresses(peer);
        Ok(())
    }

    fn clear_recovery_addresses(&mut self, scope_id: Uuid) {
        let Some(scope) = self.recovery_addresses.remove(&scope_id) else {
            return;
        };
        for peer in scope.addresses.into_keys() {
            self.reconcile_policy_addresses(peer);
            self.forget_transfer_history_if_unretained(peer);
        }
    }

    fn expire_recovery_addresses(&mut self) {
        let now = tokio::time::Instant::now();
        let expired = self
            .recovery_addresses
            .iter()
            .filter_map(|(scope, addresses)| (addresses.expires_at <= now).then_some(*scope))
            .collect::<Vec<_>>();
        for scope in expired {
            self.clear_recovery_addresses(scope);
        }
        self.recovery_quarantine
            .retain(|_, expires_at| *expires_at > now);
    }

    fn expire_learned_addresses(&mut self) {
        let now = tokio::time::Instant::now();
        let expired = self
            .learned_addresses
            .iter()
            .filter_map(|(peer, addresses)| (addresses.expires_at <= now).then_some(*peer))
            .collect::<Vec<_>>();
        for peer in expired {
            let Some(_) = self.learned_addresses.remove(&peer) else {
                continue;
            };
            self.reconcile_policy_addresses(peer);
            self.forget_transfer_history_if_unretained(peer);
        }
    }

    fn expire_opportunistic_addresses(&mut self) {
        let now = tokio::time::Instant::now();
        let expired = self
            .opportunistic_addresses
            .iter()
            .filter_map(|(peer, addresses)| (addresses.expires_at <= now).then_some(*peer))
            .collect::<Vec<_>>();
        for peer in expired {
            self.remove_opportunistic_addresses(peer);
        }
    }

    fn handle_command(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::AddLearnedAddress {
                peer,
                address,
                response,
            } => {
                let result = self.add_learned_address(peer, address);
                let _ = response.send(result);
            }
            Command::AddRecoveryAddresses {
                scope,
                peer,
                addresses,
                expires_at_unix_seconds,
                response,
            } => {
                let result =
                    self.add_recovery_addresses(scope, peer, addresses, expires_at_unix_seconds);
                let _ = response.send(result);
            }
            Command::ClearRecoveryAddresses { scope, response } => {
                self.clear_recovery_addresses(scope);
                let _ = response.send(Ok(()));
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
                if result.is_ok() {
                    let recorded_peers = self
                        .transfer_counters
                        .keys()
                        .chain(self.path_transfer_counters.keys())
                        .copied()
                        .collect::<BTreeSet<_>>();
                    for peer in recorded_peers {
                        self.forget_transfer_history_if_unretained(peer);
                    }
                }
                let _ = response.send(result);
            }
            Command::SetMappedExternalAddress { address, response } => {
                let result = self.replace_mapped_external_address(address);
                let _ = response.send(result);
            }
            #[cfg(test)]
            Command::ClosePortMappingListener { response } => {
                let result = self
                    .port_mapping_listener
                    .context("automatic gateway mapping has no owned listener")
                    .and_then(|listener| {
                        if self.swarm.remove_listener(listener) {
                            Ok(())
                        } else {
                            bail!("automatic gateway mapping listener is already closed")
                        }
                    });
                let _ = response.send(result);
            }
            Command::Request {
                cancellation_id,
                peer,
                recipient,
                request,
                response,
                permit,
            } => {
                if response.is_closed() {
                    return Ok(false);
                }
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
                                let now = tokio::time::Instant::now();
                                let transport_tier = self.selected_transport_tier(peer);
                                self.queue_or_dispatch_request(PendingRequest {
                                    cancellation_id,
                                    peer,
                                    recipient,
                                    response_recipient: self.service.reader_config.keys().node_id(),
                                    request,
                                    request_id,
                                    request_hash,
                                    request_bytes,
                                    transport_tier,
                                    attempts: 0,
                                    deadline: now + LOGICAL_REQUEST_TIMEOUT,
                                    started_at: now,
                                    response: Some(response),
                                    _permit: permit,
                                });
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
                let endpoint_selection = self.current_advertised_endpoints();
                let mut degraded = self.transport_degradation();
                // `transport_degradation` independently reports the same
                // rejected set. Keep status stable if this command observes a
                // listener transition between the two snapshots.
                degraded.extend(endpoint_selection.rejected);
                degraded.sort();
                degraded.dedup();
                let mut known_peers = self
                    .swarm
                    .connected_peers()
                    .copied()
                    .collect::<BTreeSet<_>>();
                known_peers.extend(self.transfer_counters.keys().copied());
                let mut peers = known_peers
                    .into_iter()
                    .map(|peer| {
                        let mut active_paths = self
                            .connection_paths
                            .values()
                            .filter_map(|(connected_peer, path)| {
                                (*connected_peer == peer).then_some(*path)
                            })
                            .collect::<Vec<_>>();
                        active_paths.sort();
                        active_paths.dedup();
                        let path_transfers = self
                            .path_transfer_counters
                            .get(&peer)
                            .into_iter()
                            .flat_map(|counters| counters.iter())
                            .map(|(path, counter)| P2pPathTransfer {
                                path: *path,
                                application_bytes_sent: counter.sent,
                                application_bytes_received: counter.received,
                            })
                            .collect();
                        P2pPeerStatus {
                            peer_id: peer.to_string(),
                            active_paths,
                            last_application_path: self.last_application_paths.get(&peer).copied(),
                            application_bytes_sent: self
                                .transfer_counters
                                .get(&peer)
                                .map_or(0, |counter| counter.sent),
                            application_bytes_received: self
                                .transfer_counters
                                .get(&peer)
                                .map_or(0, |counter| counter.received),
                            path_transfers,
                        }
                    })
                    .collect::<Vec<_>>();
                peers.sort_by(|left, right| left.peer_id.cmp(&right.peer_id));
                let mut active_sessions = self
                    .sessions
                    .values()
                    .map(|session| P2pActiveSession {
                        sequence: session.sequence,
                        peer_id: session.peer.to_string(),
                        path: session.path,
                        direction: session.direction,
                        opened_at_unix_seconds: session.opened_at_unix_seconds,
                    })
                    .collect::<Vec<_>>();
                active_sessions.sort_by_key(|session| session.sequence);
                let recent_sessions = self.recent_sessions.iter().cloned().collect();
                let path_metrics = self
                    .path_metrics
                    .iter()
                    .map(|(path, metrics)| P2pPathMetrics {
                        path: *path,
                        sessions_opened: metrics.sessions_opened,
                        sessions_closed: metrics.sessions_closed,
                        dial_failures: metrics.dial_failures,
                        requests_succeeded: metrics.requests_succeeded,
                        requests_failed: metrics.requests_failed,
                        request_latency_millis_total: metrics.request_latency_millis_total,
                        application_bytes_sent: metrics.application_bytes_sent,
                        application_bytes_received: metrics.application_bytes_received,
                    })
                    .collect();
                let _ = response.send(P2pStatus {
                    peer_id: self.swarm.local_peer_id().to_string(),
                    network_ready: self.network_ready(),
                    direct_listeners_configured: self.direct_listeners.len(),
                    direct_listeners_active: self.active_direct_listeners.len(),
                    relay_reservations_configured: self.relay_reservations.len(),
                    relay_reservations_active: self.active_relay_listeners.len(),
                    tor_mode: self.tor_mode,
                    onion_service_configured: self.tor_mode.enabled(),
                    onion_service_reachable: self.active_tor_listener,
                    port_mapping_enabled: self.port_mapping_enabled,
                    port_mapping_external_address: self
                        .mapped_external_address
                        .as_ref()
                        .map(ToString::to_string),
                    degraded,
                    listen_addresses,
                    advertised_addresses: endpoint_selection.addresses,
                    peers,
                    active_sessions,
                    recent_sessions,
                    path_metrics,
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
                    if let Err(error) = self.add_identified_address(peer_id, address.clone()) {
                        tracing::debug!(%peer_id, %address, %error, "ignored unusable Identify address");
                    }
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
                        self.classify_dcutr_connection(event.remote_peer_id, *connection_id);
                        self.observe_established_transport(event.remote_peer_id, *connection_id);
                        self.schedule_duplicate_session_collapse(
                            event.remote_peer_id,
                            *connection_id,
                        );
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
                        self.classify_failed_dcutr(event.remote_peer_id);
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
                if self.port_mapping_listener == Some(listener_id)
                    && let Some(port) = super::port_mapping::ipv4_quic_listener(&address)
                        .and_then(|(_, port)| NonZeroU16::new(port))
                {
                    self.port_mapping_listener_active = true;
                    self.port_mapping_listener_state
                        .send_replace(PortMappingListenerState::Active(port));
                }
                if self.relay_listeners.contains_key(&listener_id) {
                    self.active_relay_listeners.insert(listener_id);
                }
                if self
                    .tor_listener
                    .as_ref()
                    .is_some_and(|(tor_listener, _)| *tor_listener == listener_id)
                {
                    self.active_tor_listener = true;
                }
                self.complete_startup_if_ready();
                tracing::info!(%address, "libp2p listening");
            }
            SwarmEvent::ExpiredListenAddr {
                listener_id,
                address,
            } => {
                if self
                    .tor_listener
                    .as_ref()
                    .is_some_and(|(tor_listener, _)| *tor_listener == listener_id)
                {
                    self.active_tor_listener = false;
                }
                tracing::warn!(%address, "libp2p listen address expired");
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
                self.observe_port_mapping_listener_closed(listener_id);
                if self.relay_listeners.remove(&listener_id).is_some() {
                    self.active_relay_listeners.remove(&listener_id);
                }
                let tor_closed = self
                    .tor_listener
                    .as_ref()
                    .is_some_and(|(tor_listener, _)| *tor_listener == listener_id);
                if tor_closed {
                    self.active_tor_listener = false;
                    self.tor_listener = None;
                }
                let direct_exhausted = !self.direct_listeners.is_empty()
                    && self.active_direct_listeners.is_empty()
                    && self.closed_direct_listeners.len() == self.direct_listeners.len();
                let all_paths_exhausted = (self.direct_listeners.is_empty() || direct_exhausted)
                    && self.relay_reservations.is_empty()
                    && self.tor_listener.is_none();
                // An expired address is a recoverable reachability transition,
                // but a closed Arti listener means its acceptor has terminated
                // and cannot be reconstructed from inside this Swarm.  Exit so
                // the daemon's process supervisor can recreate the transport;
                // otherwise auto/prefer mode would silently lose its promised
                // fallback while an IP listener kept the event loop alive.
                if tor_closed || all_paths_exhausted {
                    let error = if tor_closed {
                        format!("Arti onion listener closed: {reason:?}")
                    } else {
                        format!("all configured libp2p listeners closed: {reason:?}")
                    };
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
                let policy_dial = self.policy_dials.remove(&connection_id);
                let policy_dial_peer = policy_dial.as_ref().map(|dial| dial.peer);
                let path = connected_point_path(&endpoint);
                let dialer = matches!(&endpoint, ConnectedPoint::Dialer { .. });
                // DCUtR may report the upgraded connection before or after the
                // generic swarm event. Do not let the latter erase the more
                // specific classification when it arrives second.
                let recorded = self
                    .connection_paths
                    .get(&connection_id)
                    .map(|(_, path)| *path);
                let established_path = merge_established_path(recorded, path);
                self.connection_paths
                    .insert(connection_id, (peer_id, established_path));
                self.connection_dialers.insert(connection_id, dialer);
                self.record_session_open(
                    connection_id,
                    peer_id,
                    established_path,
                    if dialer {
                        P2pSessionDirection::Outbound
                    } else {
                        P2pSessionDirection::Inbound
                    },
                );
                if established_path == P2pPath::Direct {
                    let local_prefers_dialer = self.swarm.local_peer_id() < &peer_id;
                    let paired_punch = self.connection_paths.iter().find_map(
                        |(candidate, (candidate_peer, candidate_path))| {
                            (*candidate != connection_id
                                && *candidate_peer == peer_id
                                && *candidate_path == P2pPath::HolePunched
                                && self.connection_dialers.get(candidate).copied()
                                    != Some(local_prefers_dialer))
                            .then_some(*candidate)
                        },
                    );
                    if let Some(paired_punch) = paired_punch {
                        self.classify_dcutr_connection(peer_id, paired_punch);
                    }
                }
                let path = self
                    .connection_paths
                    .get(&connection_id)
                    .map(|(_, path)| *path)
                    .unwrap_or(established_path);
                if !transport_path_allowed(self.tor_mode, path) {
                    self.collapsing_connections.insert(connection_id);
                    if !self.swarm.close_connection(connection_id) {
                        self.collapsing_connections.remove(&connection_id);
                    }
                    tracing::warn!(%peer_id, ?path, "closing a transport-policy-forbidden session");
                    return;
                }
                if let Some(dial) = &policy_dial
                    && (dial.peer != peer_id
                        || path_preference_rank(self.tor_mode, path) != dial.tier)
                {
                    tracing::warn!(
                        peer = %peer_id,
                        expected_peer = %dial.peer,
                        expected_tier = dial.tier,
                        ?path,
                        "policy dial established on an unexpected peer or transport tier"
                    );
                }
                self.observe_established_transport(peer_id, connection_id);
                self.schedule_duplicate_session_collapse(peer_id, connection_id);
                self.drain_queued_requests(peer_id);
                if let Some(dial_peer) = policy_dial_peer
                    && dial_peer != peer_id
                {
                    self.forget_transport_selection_if_unretained(dial_peer);
                }
                tracing::info!(peer = %peer_id, ?endpoint, "libp2p connection established");
            }
            SwarmEvent::ConnectionClosed {
                connection_id,
                peer_id,
                num_established,
                cause,
                ..
            } => {
                let closed_path = self
                    .connection_paths
                    .remove(&connection_id)
                    .map(|(_, path)| path);
                if let Some(path) = closed_path {
                    self.remember_closed_connection_path(connection_id, peer_id, path);
                }
                self.policy_dials.remove(&connection_id);
                self.connection_dialers.remove(&connection_id);
                self.relay_retirement.remove(&connection_id);
                self.duplicate_retirement.remove(&connection_id);
                let unhealthy = self.unhealthy_connections.remove(&connection_id);
                self.record_session_close(connection_id, cause.is_some() || unhealthy);
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
                if let Some(promotion) = self.transport_promotions.get(&peer_id)
                    && !self.healthy_connection_at_tier(peer_id, promotion.tier, None)
                {
                    self.transport_promotions.remove(&peer_id);
                }
                self.restore_selected_transport_after_close(peer_id, closed_path);
                self.drain_queued_requests(peer_id);
                self.forget_transport_selection_if_unretained(peer_id);
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
                ..
            } => {
                tracing::warn!(peer = ?peer_id, %error, "libp2p outgoing connection failed");
                if let Some(dial) = self.policy_dials.remove(&connection_id) {
                    self.record_dial_failure_path(dial.path);
                    if dial.kind == PolicyDialKind::Selected
                        && self.selected_transport_tier(dial.peer) == dial.tier
                        && !self.healthy_connection_at_tier(dial.peer, dial.tier, None)
                        && !self.activate_fallback(dial.peer)
                        && self.has_outstanding_request(dial.peer)
                    {
                        self.fail_queued_requests(
                            dial.peer,
                            "libp2p exhausted every configured transport tier",
                        );
                    }
                    self.drain_queued_requests(dial.peer);
                    self.forget_transport_selection_if_unretained(dial.peer);
                } else if let Some(peer) = peer_id {
                    self.record_dial_failure(peer);
                    self.forget_transport_selection_if_unretained(peer);
                }
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
                let path = self.application_path(connection_id);
                if let Some(path) = path {
                    self.last_application_paths.insert(peer, path);
                }
                match message {
                    request_response::Message::Request {
                        request,
                        channel,
                        request_id,
                    } => {
                        if let Ok(bytes) = cbor_wire_len(&request) {
                            self.record_transfer(peer, path, 0, bytes);
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
                                                .insert(request_id, (peer, path, response_bytes));
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
                                path,
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
                            let request_peer = pending.peer;
                            if pending.peer == peer {
                                self.record_transfer(
                                    peer,
                                    path,
                                    pending.request_bytes,
                                    response_bytes.unwrap_or(0),
                                );
                            }
                            let result = if pending.peer == peer {
                                validate_outbound_response(response, &pending)
                            } else {
                                Err(anyhow::anyhow!("libp2p response came from the wrong peer"))
                            };
                            self.record_request_result(path, pending.started_at, result.is_ok());
                            if let Some(path) = path {
                                let actual_tier = path_preference_rank(self.tor_mode, path);
                                if actual_tier != pending.transport_tier {
                                    tracing::warn!(
                                        %peer,
                                        expected_tier = pending.transport_tier,
                                        actual_tier,
                                        ?path,
                                        "request succeeded on a non-selected transport tier"
                                    );
                                    self.observe_established_transport(peer, connection_id);
                                }
                            }
                            let mut pending = pending;
                            pending.finish(result);
                            self.forget_transport_selection_if_unretained(request_peer);
                        }
                    }
                }
            }
            request_response::Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => {
                if let Some(mut pending) = self.pending_requests.remove(&request_id) {
                    let request_peer = pending.peer;
                    let path = self.request_failure_path(peer, connection_id);
                    self.record_request_result(
                        path.or_else(|| self.selected_path_hint(peer)),
                        pending.started_at,
                        false,
                    );

                    let attempted_tier = pending.transport_tier;
                    let actual_tier = path
                        .map(|path| path_preference_rank(self.tor_mode, path))
                        .unwrap_or(attempted_tier);
                    let used_wrong_tier = actual_tier != attempted_tier;

                    let healthy_duplicate =
                        self.healthy_connection_at_tier(peer, attempted_tier, Some(connection_id));
                    if self
                        .connection_paths
                        .get(&connection_id)
                        .is_some_and(|(candidate, _)| *candidate == peer)
                    {
                        self.unhealthy_connections.insert(connection_id);
                        if !self.swarm.close_connection(connection_id) {
                            self.unhealthy_connections.remove(&connection_id);
                        }
                    }

                    if !pending.caller_waiting() {
                        self.forget_transport_selection_if_unretained(request_peer);
                        return;
                    }
                    if used_wrong_tier {
                        tracing::warn!(
                            %peer,
                            attempted_tier,
                            actual_tier,
                            ?path,
                            "request failed on a non-selected transport tier"
                        );
                        self.ensure_selected_transport(peer);
                        self.queue_or_dispatch_request(pending);
                        self.forget_transport_selection_if_unretained(request_peer);
                        return;
                    }
                    let advanced = !healthy_duplicate
                        && self.selected_transport_tier(peer) <= attempted_tier
                        && self.activate_fallback(peer);
                    let selected_tier = self.selected_transport_tier(peer);
                    if healthy_duplicate || advanced || selected_tier != attempted_tier {
                        self.queue_or_dispatch_request(pending);
                    } else {
                        pending.finish(Err(anyhow::anyhow!("libp2p request failed: {error}")));
                    }
                    self.forget_transport_selection_if_unretained(request_peer);
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
                if let Some((expected_peer, path, bytes)) =
                    self.pending_response_bytes.remove(&request_id)
                    && expected_peer == peer
                {
                    self.record_transfer(peer, path, bytes, 0);
                }
            }
        }
    }

    fn retire_idle_relay_connections(&mut self) {
        let now = tokio::time::Instant::now();
        let finished = self
            .relay_retirement
            .iter()
            .filter_map(|(connection_id, (peer, deadline))| {
                let still_punched = self.healthy_path_exists(*peer, P2pPath::HolePunched);
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
            let mut awaiting_close = false;
            if should_close {
                self.collapsing_connections.insert(connection_id);
                if self.swarm.close_connection(connection_id) {
                    awaiting_close = true;
                    tracing::debug!(
                        %peer,
                        ?connection_id,
                        "retiring idle relay connection after successful DCUtR"
                    );
                } else {
                    self.collapsing_connections.remove(&connection_id);
                }
            }
            if !awaiting_close {
                self.drain_queued_requests(peer);
            }
        }
    }

    fn schedule_duplicate_session_collapse(&mut self, peer: PeerId, new_connection: ConnectionId) {
        let connections = self
            .connection_paths
            .iter()
            .filter_map(|(connection, (candidate, path))| {
                (*candidate == peer).then_some((
                    *connection,
                    *path,
                    self.connection_dialers
                        .get(connection)
                        .copied()
                        .unwrap_or(false),
                ))
            })
            .collect::<Vec<_>>();
        if connections.len() < 2 {
            return;
        }
        let best_rank = connections
            .iter()
            .map(|(_, path, _)| path_preference_rank(self.tor_mode, *path))
            .min()
            .expect("two connections have a best rank");
        let deadline = tokio::time::Instant::now() + RELAY_RETIREMENT_GRACE;

        // A relay reservation is tied to the exact outbound connection that
        // created its virtual listener, but libp2p does not expose that
        // connection ID with the listener event.  Keep equal-rank duplicate
        // sessions to configured relays: direction-based collapse could
        // otherwise select an inbound application/DHT connection and close
        // the outbound reservation underneath every circuit using it.
        // Different transport tiers are retired separately, only after the
        // selected-tier promotion has survived its health grace period.
        if self.relay_reservation_peers.contains(&peer) {
            return;
        }

        let local_prefers_dialer = self.swarm.local_peer_id() < &peer;
        let preferred_direction_exists = connections.iter().any(|(_, path, dialer)| {
            path_preference_rank(self.tor_mode, *path) == best_rank
                && *dialer == local_prefers_dialer
        });
        if !preferred_direction_exists {
            return;
        }
        for (connection, path, dialer) in &connections {
            if path_preference_rank(self.tor_mode, *path) == best_rank
                && *dialer != local_prefers_dialer
            {
                self.duplicate_retirement
                    .insert(*connection, (peer, deadline));
            }
        }
        if local_prefers_dialer {
            let older_preferred_exists = connections.iter().any(|(connection, path, dialer)| {
                *connection != new_connection
                    && path_preference_rank(self.tor_mode, *path) == best_rank
                    && *dialer
            });
            if older_preferred_exists
                && self
                    .connection_dialers
                    .get(&new_connection)
                    .copied()
                    .unwrap_or(false)
                && self
                    .connection_paths
                    .get(&new_connection)
                    .is_some_and(|(_, path)| {
                        path_preference_rank(self.tor_mode, *path) == best_rank
                    })
            {
                self.duplicate_retirement
                    .insert(new_connection, (peer, deadline));
            }
        }
    }

    fn retire_duplicate_sessions(&mut self) {
        let now = tokio::time::Instant::now();
        let finished = self
            .duplicate_retirement
            .iter()
            .filter_map(|(connection, (peer, deadline))| {
                if *deadline > now {
                    return None;
                }
                let busy = self
                    .pending_requests
                    .values()
                    .any(|pending| pending.peer == *peer)
                    || self
                        .active_inbound_requests
                        .values()
                        .any(|candidate| *candidate == *peer);
                if busy {
                    return None;
                }
                let Some((_, path)) = self.connection_paths.get(connection) else {
                    return Some((*connection, *peer, false));
                };
                let replacement_exists = self.healthy_replacement_exists(
                    *peer,
                    *connection,
                    path_preference_rank(self.tor_mode, *path),
                );
                Some((*connection, *peer, replacement_exists))
            })
            .collect::<Vec<_>>();
        for (connection, peer, should_close) in finished {
            self.duplicate_retirement.remove(&connection);
            let mut awaiting_close = false;
            if should_close {
                self.collapsing_connections.insert(connection);
                if self.swarm.close_connection(connection) {
                    awaiting_close = true;
                } else {
                    self.collapsing_connections.remove(&connection);
                }
            }
            if !awaiting_close {
                self.drain_queued_requests(peer);
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

pub async fn run_peer_exchange(node: Arc<Mutex<Node>>, p2p: P2pClient) -> Result<()> {
    loop {
        if let Err(error) = exchange_guild_endpoints_once(node.clone(), &p2p).await {
            tracing::warn!(%error, "guild peer endpoint exchange failed");
        }
        tokio::time::sleep(PEER_EXCHANGE_INTERVAL).await;
    }
}

pub async fn run_relay_membership_sync(node: Arc<Mutex<Node>>, p2p: P2pClient) -> Result<()> {
    loop {
        if let Err(error) = sync_relay_membership_once(node.clone(), &p2p).await {
            tracing::warn!(%error, "relay membership synchronization failed");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn sync_relay_membership_once(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let guild = node_blocking(node, |node| node.guild_summary()).await?;
    let members = guild
        .filter(|guild| matches!(guild.phase, GuildPhase::Active))
        .into_iter()
        .flat_map(|guild| guild.peers)
        .map(|peer| peer.member.node_id.libp2p_peer_id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    p2p.set_relay_members(members).await
}

async fn refresh_guild_endpoints(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let (guild, local_id) = node_blocking(node.clone(), |node| {
        Ok((node.guild_summary()?, node.keys().node_id()))
    })
    .await?;
    let Some(guild) = guild else {
        return Ok(());
    };
    if !matches!(guild.phase, GuildPhase::Active) {
        return Ok(());
    }
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
        let endpoint = match select_durable_endpoint_record(node.clone(), member, records).await {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%member, %error, "guild member published conflicting endpoints");
                continue;
            }
        };
        apply_endpoint_record(p2p, endpoint).await?;
    }
    Ok(())
}

async fn exchange_guild_endpoints_once(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let local_endpoints = advertised_p2p_endpoints(p2p).await?;
    let endpoint_expiry = unix_seconds()
        .checked_add(DHT_TTL.as_secs())
        .context("peer-exchange endpoint expiry overflow")?;
    node_blocking(node.clone(), move |node| {
        node.refresh_peer_exchange_endpoint(local_endpoints, endpoint_expiry)
            .map(|_| ())
    })
    .await?;
    let (guild, local_id) = node_blocking(node.clone(), |node| {
        Ok((node.guild_summary()?, node.keys().node_id()))
    })
    .await?;
    let Some(guild) = guild.filter(|guild| matches!(guild.phase, GuildPhase::Active)) else {
        return Ok(());
    };
    let allowed = guild
        .peers
        .iter()
        .map(|peer| peer.member.node_id)
        .collect::<BTreeSet<_>>();
    let mut queries = FuturesUnordered::new();
    for member in allowed.iter().copied().filter(|member| *member != local_id) {
        queries.push(async move { (member, p2p.exchange_endpoints(member, guild.guild_id).await) });
    }
    while let Some((source, result)) = queries.next().await {
        let records = match result {
            Ok(records) => records,
            Err(error) => {
                tracing::debug!(%source, %error, "peer endpoint exchange request failed");
                continue;
            }
        };
        for record in records {
            let publisher = record.value.publisher;
            if !allowed.contains(&publisher) {
                tracing::warn!(%source, %publisher, "peer gossiped an endpoint outside the guild");
                continue;
            }
            let selected = match select_durable_endpoint_record(
                node.clone(),
                publisher,
                vec![DhtRecord {
                    publisher: None,
                    value: canonical_bytes(&record)?,
                }],
            )
            .await
            {
                Ok(selected) => selected,
                Err(error) => {
                    tracing::warn!(%source, %publisher, %error, "rejected conflicting peer-exchanged endpoint");
                    continue;
                }
            };
            if let Some(endpoint) = selected
                && let Err(error) = apply_endpoint_record(p2p, endpoint).await
            {
                tracing::debug!(%publisher, %error, "could not apply peer-exchanged endpoint");
            }
        }
    }
    Ok(())
}

async fn apply_endpoint_record(
    p2p: &P2pClient,
    endpoint: SignedRecord<mb_core::EndpointRecord>,
) -> Result<()> {
    let member = endpoint.value.publisher;
    let expires_at_unix_seconds = endpoint.value.expires_at_unix_seconds;
    let mut addresses = Vec::with_capacity(endpoint.value.endpoints.len());
    for value in endpoint.value.endpoints {
        let address = value
            .parse::<Multiaddr>()
            .with_context(|| format!("malformed signed endpoint {value}"))?;
        if address.iter().last() != Some(libp2p::multiaddr::Protocol::P2p(member.libp2p_peer_id()?))
            || !onion_address_matches_node(&address, member)
        {
            bail!("signed endpoint is bound to another peer identity");
        }
        addresses.push(address);
    }
    p2p.replace_learned_peer_addresses(member, addresses, expires_at_unix_seconds)
        .await
}

async fn publish_dht_once(node: Arc<Mutex<Node>>, p2p: &P2pClient) -> Result<()> {
    let endpoints = available_p2p_endpoints(p2p).await?;
    let local_id = node_blocking(node.clone(), |node| Ok(node.keys().node_id())).await?;
    let local_peer = p2p.local_peer_id();
    let published_checkpoint_hash = if endpoints.is_empty() {
        tracing::debug!("DHT publication deferred until a local endpoint is reachable");
        None
    } else {
        let expires = unix_seconds()
            .checked_add(DHT_TTL.as_secs())
            .context("DHT publication expiry overflow")?;
        let probe_subjects = node_blocking(node.clone(), |node| {
            node.dht_recovery_sequence_probe_subjects()
        })
        .await?;
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
        Some(publications.checkpoint_hash)
    };
    let checkpoint_hash = match published_checkpoint_hash {
        Some(hash) => hash,
        None => {
            let Some(hash) =
                node_blocking(node.clone(), |node| node.dht_readiness_checkpoint_hash()).await?
            else {
                return Ok(());
            };
            hash
        }
    };

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
    let mut certified_observations = Vec::new();
    let mut rejected_providers = HashSet::new();
    let mut considered_publishers = HashSet::new();
    while let Some((provider, records)) = bundle_queries.next().await {
        let Ok(records) = records else {
            tracing::warn!(%provider, "DHT readiness provider lookup failed");
            continue;
        };
        let observation = match select_recovery_bundle_candidate(
            node.clone(),
            &provider,
            local_id,
            records,
        )
        .await
        {
            Ok(Some(observation)) => observation,
            Ok(None) => continue,
            Err(error) => {
                rejected_providers.insert(provider.clone());
                tracing::warn!(%provider, %error, "rejected conflicting DHT readiness records");
                continue;
            }
        };
        let publisher = observation.selected.value.publisher;
        let expires_at = observation.selected.value.expires_at_unix_seconds;
        if validate_ready_bundle(
            node.clone(),
            &provider,
            checkpoint_hash,
            observation.selected.clone(),
        )
        .await
        .is_ok()
        {
            considered_publishers.insert(publisher);
            confirmations.push((publisher, expires_at));
            certified_observations.push(observation);
        }
    }
    for (provider, bundle) in retained_recovery_bundles(node.clone(), local_id).await? {
        let publisher = bundle.value.publisher;
        if rejected_providers.contains(&provider) || considered_publishers.contains(&publisher) {
            continue;
        }
        let expires_at = bundle.value.expires_at_unix_seconds;
        if validate_ready_bundle(node.clone(), &provider, checkpoint_hash, bundle)
            .await
            .is_ok()
        {
            considered_publishers.insert(publisher);
            confirmations.push((publisher, expires_at));
        }
    }
    node_blocking(node, move |node| {
        let checkpoint = node.checkpoint(&checkpoint_hash)?;
        node.retain_checkpoint_recovery_records(&checkpoint, certified_observations)?;
        node.update_seed_recovery_readiness(checkpoint_hash, confirmations)
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

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RecoveryDiscoveryPending(&'static str);

#[derive(Clone)]
struct RecoveryCandidate {
    publisher: NodeId,
    locator: mb_core::RecoveryLocator,
    observation: CheckpointRecoveryObservation,
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
    let _recovery_permit = p2p
        .cold_recovery_permit
        .clone()
        .acquire_owned()
        .await
        .context("libp2p event loop stopped")?;
    let local_target = restore_target.to_path_buf();
    if let Some(local) = node_blocking(node.clone(), move |node| {
        node.resume_local_recovery(&local_target)
    })
    .await?
    {
        return Ok(DhtRecoveryResult {
            guild_id: local.guild_id,
            checkpoint_hash: local.checkpoint_hash,
            generation: local.generation,
            revision_id: local.revision_id,
        });
    }
    let deadline = tokio::time::Instant::now() + DHT_RECOVERY_DISCOVERY_TIMEOUT;
    loop {
        match recover_from_dht_once(node.clone(), p2p, restore_target).await {
            Ok(result) => return Ok(result),
            Err(error) if error.downcast_ref::<RecoveryDiscoveryPending>().is_some() => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(error).context(format!(
                        "recovery discovery timed out after {} seconds",
                        DHT_RECOVERY_DISCOVERY_TIMEOUT.as_secs()
                    ));
                }
                tracing::debug!(%error, "DHT recovery discovery is not ready; retrying");
                tokio::time::sleep(DHT_RECOVERY_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn recover_from_dht_once(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    restore_target: &std::path::Path,
) -> Result<DhtRecoveryResult> {
    let subject = node_blocking(node.clone(), |node| Ok(node.keys().node_id())).await?;
    let providers = p2p
        .get_providers(recovery_mailbox_key(subject))
        .await
        .context(RecoveryDiscoveryPending(
            "Kademlia recovery provider lookup is not ready",
        ))?;
    tracing::debug!(subject = %subject, providers = providers.len(), "DHT recovery provider query completed");
    let mut bundle_queries = FuturesUnordered::new();
    for provider in providers {
        let key = recovery_bundle_key(subject, &provider);
        bundle_queries.push(async move { (provider, p2p.get_record(key).await) });
    }
    let mut candidates = Vec::new();
    let mut rejected_providers = HashSet::new();
    while let Some((provider, records)) = bundle_queries.next().await {
        let Ok(records) = records else {
            tracing::warn!(%provider, "recovery provider lookup failed");
            continue;
        };
        let observation = match select_recovery_bundle_candidate(
            node.clone(),
            &provider,
            subject,
            records,
        )
        .await
        {
            Ok(Some(observation)) => observation,
            Ok(None) => continue,
            Err(error) => {
                rejected_providers.insert(provider.clone());
                tracing::warn!(%provider, %error, "recovery provider published conflicting records");
                continue;
            }
        };
        let provider_for_check = provider.clone();
        match node_blocking(node.clone(), move |node| {
            decode_recovery_candidate(node, &provider_for_check, observation)
        })
        .await
        {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => {
                tracing::warn!(%provider, %error, "ignored invalid recovery candidate");
            }
        }
    }
    for (provider, bundle) in retained_recovery_bundles(node.clone(), subject).await? {
        if rejected_providers.contains(&provider)
            || candidates
                .iter()
                .any(|candidate| candidate.publisher == bundle.value.publisher)
        {
            continue;
        }
        match node_blocking(node.clone(), move |node| {
            decode_recovery_candidate(
                node,
                &provider,
                CheckpointRecoveryObservation {
                    provider_peer_id: provider.clone(),
                    selected: bundle,
                    observations: Vec::new(),
                },
            )
        })
        .await
        {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => tracing::warn!(%error, "ignored retained recovery candidate"),
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
    tracing::debug!(
        subject = %subject,
        heads = candidates_by_head.len(),
        candidates = candidates_by_head.values().map(Vec::len).sum::<usize>(),
        "DHT recovery candidates validated"
    );
    let mut generations = candidates_by_head
        .iter()
        .filter(|(_, candidates)| candidates.len() >= 3)
        .map(|((generation, _, _), _)| *generation)
        .collect::<Vec<_>>();
    generations.sort_unstable_by(|left, right| right.cmp(left));
    generations.dedup();
    if generations.is_empty() {
        return Err(RecoveryDiscoveryPending(
            "Kademlia returned no recovery head confirmed by three publishers",
        )
        .into());
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
    } = selected.ok_or(RecoveryDiscoveryPending(
        "no advertised recovery head could be certified",
    ))?;
    let recovered_endpoint_sequence_floor = candidates
        .iter()
        .map(|candidate| candidate.locator.subject_endpoint_sequence_floor)
        .max()
        .unwrap_or(0);
    let recovery_observations = candidates
        .iter()
        .map(|candidate| candidate.observation.clone())
        .collect();
    let checkpoint_for_attempt = checkpoint.clone();
    node_blocking(node.clone(), move |node| {
        node.pin_recovery_attempt(&checkpoint_for_attempt, recovery_observations)?;
        node.recover_endpoint_publication_sequence_floor(
            guild_id,
            recovered_endpoint_sequence_floor,
        )
    })
    .await?;

    // Recovery is an outbound operation and does not require the recovering
    // node's listener to be reachable at this exact instant.  The durable
    // roster permits an empty local endpoint set until the onion service (or
    // another ingress path) is advertised again.
    let local_endpoints = available_p2p_endpoints(p2p).await?;
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
        let mut endpoints_expire_at = None;
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.publisher == peer.member.node_id)
        {
            peer.endpoints = candidate.locator.endpoints.clone();
            endpoints_expire_at = Some(candidate.locator.expires_at_unix_seconds);
        }
        match select_durable_endpoint_record(
            node.clone(),
            peer.member.node_id,
            endpoint_records
                .remove(&peer.member.node_id)
                .unwrap_or_default(),
        )
        .await
        {
            Ok(Some(endpoint)) => {
                endpoints_expire_at = Some(endpoint.value.expires_at_unix_seconds);
                peer.endpoints = endpoint.value.endpoints;
            }
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
            usable_endpoints.push((endpoint.clone(), address));
        }
        if let Some(expires_at_unix_seconds) = endpoints_expire_at {
            let addresses = usable_endpoints
                .iter()
                .map(|(_, address)| address.clone())
                .collect();
            if let Err(error) = p2p
                .replace_learned_peer_addresses(
                    peer.member.node_id,
                    addresses,
                    expires_at_unix_seconds,
                )
                .await
            {
                tracing::warn!(member = %peer.member.node_id, %error, "ignored unusable endpoint set");
                usable_endpoints.clear();
            }
        }
        peer.endpoints = usable_endpoints
            .into_iter()
            .map(|(endpoint, _)| endpoint)
            .collect();
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
    let scope = Uuid::new_v4();
    let result = async {
        for candidate in &candidates {
            let addresses = candidate
                .locator
                .endpoints
                .iter()
                .filter_map(|endpoint| endpoint.parse::<Multiaddr>().ok())
                .collect::<Vec<_>>();
            if let Err(error) = p2p
                .add_recovery_addresses(
                    scope,
                    candidate.publisher,
                    addresses,
                    candidate.locator.expires_at_unix_seconds,
                )
                .await
            {
                tracing::debug!(publisher = %candidate.publisher, %error, "candidate endpoints were not usable");
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
    .await;
    if let Err(error) = p2p.clear_recovery_addresses(scope).await {
        tracing::warn!(%error, "could not clear attempt-scoped recovery endpoints");
    }
    result
}

fn decode_recovery_candidate(
    node: &Node,
    provider_peer_id: &str,
    observation: CheckpointRecoveryObservation,
) -> Result<RecoveryCandidate> {
    let bundle = &observation.selected;
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
        observation,
    })
}

fn select_recovery_bundle(
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<SignedRecord<mb_core::RecoveryBundle>>> {
    let observations = recovery_bundle_observations(provider_peer_id, subject, records)?;
    let Some(bytes) = select_current_observation(observations)? else {
        return Ok(None);
    };
    Ok(Some(decode_canonical(&bytes)?))
}

fn recovery_bundle_observations(
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Vec<DhtRecordObservation>> {
    let mut observations = Vec::new();
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
        observations.push(DhtRecordObservation {
            sequence: bundle.value.sequence,
            expires_at_unix_seconds: bundle.value.expires_at_unix_seconds,
            bytes: canonical_bytes(&bundle)?,
        });
    }
    Ok(observations)
}

fn select_endpoint_record(
    publisher: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<SignedRecord<mb_core::EndpointRecord>>> {
    let observations = endpoint_record_observations(publisher, records)?;
    let Some(bytes) = select_current_observation(observations)? else {
        return Ok(None);
    };
    Ok(Some(decode_canonical(&bytes)?))
}

async fn select_durable_endpoint_record(
    node: Arc<Mutex<Node>>,
    publisher: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<SignedRecord<mb_core::EndpointRecord>>> {
    let observations = endpoint_record_observations(publisher, records)?;
    let record_id = publisher.0;
    let selected = node_blocking(node, move |node| {
        node.observe_dht_records("dht-observed-endpoint", &record_id, observations)
    })
    .await?;
    match selected {
        Some(bytes) => select_endpoint_record(
            publisher,
            vec![DhtRecord {
                publisher: None,
                value: bytes,
            }],
        ),
        None => Ok(None),
    }
}

async fn select_recovery_bundle_candidate(
    node: Arc<Mutex<Node>>,
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<CheckpointRecoveryObservation>> {
    let observations = recovery_bundle_observations(provider_peer_id, subject, records)?;
    let mut record_id = [0_u8; 64];
    record_id[..32].copy_from_slice(&subject.0);
    record_id[32..].copy_from_slice(blake3::hash(provider_peer_id.as_bytes()).as_bytes());
    let observations_for_selection = observations.clone();
    let selected = node_blocking(node, move |node| {
        node.select_recovery_dht_records(&record_id, observations_for_selection)
    })
    .await?;
    match selected {
        Some(bytes) => Ok(select_recovery_bundle(
            provider_peer_id,
            subject,
            vec![DhtRecord {
                publisher: None,
                value: bytes,
            }],
        )?
        .map(|selected| CheckpointRecoveryObservation {
            provider_peer_id: provider_peer_id.to_owned(),
            selected,
            observations,
        })),
        None => Ok(None),
    }
}

async fn retained_recovery_bundles(
    node: Arc<Mutex<Node>>,
    subject: NodeId,
) -> Result<Vec<(String, SignedRecord<mb_core::RecoveryBundle>)>> {
    let records = node_blocking(node, move |node| node.observed_recovery_records(subject)).await?;
    let mut bundles = Vec::new();
    for (provider_hash, bytes) in records {
        let bundle: SignedRecord<mb_core::RecoveryBundle> = decode_canonical(&bytes)?;
        let provider = bundle.value.publisher.libp2p_peer_id()?.to_string();
        if blake3::hash(provider.as_bytes()).as_bytes() != &provider_hash {
            bail!("durable recovery observation is stored under another provider");
        }
        if let Some(bundle) = select_recovery_bundle(
            &provider,
            subject,
            vec![DhtRecord {
                publisher: None,
                value: bytes,
            }],
        )? {
            bundles.push((provider, bundle));
        }
    }
    Ok(bundles)
}

fn endpoint_record_observations(
    publisher: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Vec<DhtRecordObservation>> {
    let mut observations = Vec::new();
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
        observations.push(DhtRecordObservation {
            sequence: endpoint.value.sequence,
            expires_at_unix_seconds: endpoint.value.expires_at_unix_seconds,
            bytes: canonical_bytes(&endpoint)?,
        });
    }
    Ok(observations)
}

fn select_current_observation(observations: Vec<DhtRecordObservation>) -> Result<Option<Vec<u8>>> {
    let mut by_sequence = BTreeMap::<u64, ([u8; 32], Vec<u8>)>::new();
    for observation in observations {
        let hash = *blake3::hash(&observation.bytes).as_bytes();
        if let Some((existing_hash, _)) = by_sequence.get(&observation.sequence) {
            if *existing_hash != hash {
                bail!("DHT publisher forked one sequence");
            }
        } else {
            by_sequence.insert(observation.sequence, (hash, observation.bytes));
        }
    }
    Ok(by_sequence
        .last_key_value()
        .map(|(_, (_, bytes))| bytes.clone()))
}

fn valid_endpoint_values(publisher: NodeId, endpoints: &[String]) -> bool {
    if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS_PER_PEER {
        return false;
    }
    let mut unique = BTreeSet::new();
    endpoints
        .iter()
        .all(|value| unique.insert(value) && validate_published_endpoint(publisher, value).is_ok())
}

fn highest_endpoint_sequence(publisher: NodeId, records: Vec<DhtRecord>) -> Result<Option<u64>> {
    let mut observed = BTreeMap::new();
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
            insert_sequence_hash(
                &mut observed,
                endpoint.value.sequence,
                *blake3::hash(&canonical_bytes(&endpoint)?).as_bytes(),
            )?;
        }
    }
    Ok(observed.last_key_value().map(|(sequence, _)| *sequence))
}

fn highest_recovery_sequence(
    provider_peer_id: &str,
    subject: NodeId,
    records: Vec<DhtRecord>,
) -> Result<Option<u64>> {
    let mut observed = BTreeMap::new();
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
            insert_sequence_hash(
                &mut observed,
                bundle.value.sequence,
                *blake3::hash(&canonical_bytes(&bundle)?).as_bytes(),
            )?;
        }
    }
    Ok(observed.last_key_value().map(|(sequence, _)| *sequence))
}

fn insert_sequence_hash(
    observed: &mut BTreeMap<u64, [u8; 32]>,
    sequence: u64,
    hash: [u8; 32],
) -> Result<()> {
    if let Some(existing) = observed.insert(sequence, hash)
        && existing != hash
    {
        bail!("DHT publisher forked one sequence");
    }
    Ok(())
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
    let deferred_holders = Arc::new(Mutex::new(BTreeSet::new()));
    recover_local_shards_with(node, checkpoint, |group, target_index| {
        let deferred_holders = deferred_holders.clone();
        async move {
            reconstruct_shard_from_peers(p2p, &group, target_index, roster, &deferred_holders).await
        }
    })
    .await
}

async fn recover_local_shards_with<F, Fut>(
    node: Arc<Mutex<Node>>,
    checkpoint: &QuorumCheckpoint,
    mut reconstruct: F,
) -> Result<()>
where
    F: FnMut(CodingGroup, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
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
        let staged_group = group.clone();
        let guild_id = checkpoint.checkpoint.guild_id;
        let already_staged = node_blocking(node.clone(), move |node| {
            node.recovered_shard_is_staged(
                &checkpoint_hash,
                &guild_id,
                &staged_group,
                target_index as u8,
            )
        })
        .await?;
        if already_staged {
            continue;
        }
        let bytes = reconstruct(group.clone(), target_index).await?;
        if sector_root(&bytes) != target_root {
            bail!("reconstructed target shard failed its certified root");
        }
        let group = group.clone();
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
    deferred_holders: &Mutex<BTreeSet<NodeId>>,
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
        let deferred = deferred_holders
            .lock()
            .map_err(|_| anyhow::anyhow!("shard holder health lock is poisoned"))?
            .clone();
        let mut candidates = Vec::new();
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
            candidates.push((index, holder, root, sector_id));
        }
        candidates.sort_by_key(|(_, holder, _, _)| deferred.contains(holder));
        let preferred_count = candidates
            .iter()
            .take_while(|(_, holder, _, _)| !deferred.contains(holder))
            .count();
        let valid_count = shards.iter().filter(|shard| shard.is_some()).count();
        let needed = usize::from(V1_RS_DATA_SHARDS).saturating_sub(valid_count);
        let request_count = if preferred_count >= needed {
            preferred_count.min(needed.saturating_add(1))
        } else {
            candidates.len()
        };
        let mut requests = FuturesUnordered::new();
        let mut issued = Vec::with_capacity(request_count);
        for (index, holder, root, sector_id) in candidates.into_iter().take(request_count) {
            issued.push((index, holder));
            let client = p2p.clone();
            let guild_id = group.guild_id;
            let group_id = group.id;
            requests.push(async move {
                let result = if let Some(sector_id) = sector_id {
                    client.sector(holder, guild_id, sector_id).await
                } else {
                    client.parity(holder, guild_id, group_id, index as u8).await
                };
                (index, holder, root, result)
            });
        }
        while let Some((index, holder, root, result)) = requests.next().await {
            match result {
                Ok(bytes)
                    if bytes.len() == group.shard_size as usize && sector_root(&bytes) == root =>
                {
                    shards[index] = Some(bytes);
                }
                Ok(_) => tracing::warn!(
                    group = %hex::encode(group.id),
                    shard_index = index,
                    %holder,
                    "peer returned an invalid recovery shard"
                ),
                Err(error) => tracing::warn!(
                    group = %hex::encode(group.id),
                    shard_index = index,
                    %holder,
                    %error,
                    "could not fetch a recovery shard"
                ),
            }
            // Reconstruction needs any three valid shards. Dropping the
            // remaining calls cancels their event-loop ownership and permits;
            // defer those holders in later groups so the transport does not
            // accumulate one timed-out request per group.
            if shards.iter().filter(|shard| shard.is_some()).count()
                >= usize::from(V1_RS_DATA_SHARDS)
            {
                break;
            }
        }
        {
            let mut deferred = deferred_holders
                .lock()
                .map_err(|_| anyhow::anyhow!("shard holder health lock is poisoned"))?;
            for (index, holder) in issued {
                if shards[index].is_some() {
                    deferred.remove(&holder);
                } else {
                    deferred.insert(holder);
                }
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
    let publication_target = target.to_path_buf();
    if let Some(restored) = node_blocking(node.clone(), move |node| {
        node.resume_snapshot_publication(revision_id, &publication_target)
    })
    .await?
    {
        return Ok(restored);
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
    let deferred_holders = Mutex::new(BTreeSet::new());
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
        let bytes =
            reconstruct_shard_from_peers(p2p, group, target_index, &roster, &deferred_holders)
                .await?;
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
    let endpoints = available_p2p_endpoints(p2p).await?;
    if endpoints.is_empty() {
        bail!("daemon has no usable DHT endpoint");
    }
    Ok(endpoints)
}

async fn available_p2p_endpoints(p2p: &P2pClient) -> Result<Vec<String>> {
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
        endpoints
            .push(validate_published_endpoint_for_peer(peer_id, &address.to_string())?.to_string());
    }
    endpoints.sort();
    endpoints.dedup();
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

fn normalize_known_address(peer: PeerId, mut address: Multiaddr) -> Result<Multiaddr> {
    if address.iter().last() == Some(libp2p::multiaddr::Protocol::P2p(peer)) {
        address.pop();
    }
    if address.is_empty() {
        bail!("peer address has no transport components");
    }
    if !onion_address_matches_peer(&address, peer) {
        bail!("onion address identity differs from the peer identity");
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
    use futures::future::{Pending, Ready, ready};
    use libp2p::core::{Endpoint, transport::PortUse};
    use mb_core::{KeyMaterial, Seed};
    use request_response::Codec as _;
    use std::io;

    fn config(node_id: NodeId) -> P2pConfig {
        P2pConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            external_addresses: Vec::new(),
            bootstrap_addresses: Vec::new(),
            relay_reservation_addresses: Vec::new(),
            enable_dht_maintenance: true,
            enable_relay_server: true,
            enable_hole_punching: true,
            enable_port_mapping: false,
            public_endpoint: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            failure_domain: node_id.to_string(),
            configure_failure_domain: true,
            max_connections: 8,
            tor_mode: TorMode::DisableTor,
        }
    }

    #[test]
    fn tor_policy_selects_one_transport_class_and_a_bounded_fallback() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([201; 32]));
        let ip: Multiaddr = "/ip4/192.0.2.1/udp/44000/quic-v1".parse().unwrap();
        let relay: Multiaddr = format!(
            "/ip4/192.0.2.2/udp/44001/quic-v1/p2p/{}/p2p-circuit",
            keys.node_id().libp2p_peer_id().unwrap()
        )
        .parse()
        .unwrap();
        let onion = onion_listener_address(keys.node_id()).unwrap();
        let all = vec![relay.clone(), onion.clone(), ip.clone()];

        assert_eq!(
            selected_policy_addresses(TorMode::Auto, all.clone(), 0),
            (0, BTreeSet::from([ip.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::Auto, all.clone(), 1),
            (1, BTreeSet::from([relay.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::Auto, all.clone(), 2),
            (2, BTreeSet::from([onion.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::PreferTor, all.clone(), 0),
            (0, BTreeSet::from([onion.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::PreferTor, all.clone(), 1),
            (1, BTreeSet::from([ip.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::PreferTor, all.clone(), 2),
            (2, BTreeSet::from([relay.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::RequireTor, all.clone(), 0),
            (0, BTreeSet::from([onion.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::DisableTor, all.clone(), 0),
            (0, BTreeSet::from([ip.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::DisableTor, all.clone(), 1),
            (1, BTreeSet::from([relay.clone()]))
        );
        assert_eq!(
            selected_policy_addresses(TorMode::Auto, vec![onion.clone()], 1),
            (2, BTreeSet::from([onion]))
        );
        let tiers = policy_address_tiers(TorMode::Auto, all);
        assert_eq!(next_preferred_addresses(&tiers, 2), vec![ip.clone(), relay]);
        assert_eq!(next_preferred_addresses(&tiers, 1), vec![ip]);
    }

    #[test]
    fn fallback_session_waits_for_a_live_preferred_replacement_before_retirement() {
        assert!(!should_retire_non_policy_connection(
            TorMode::Auto,
            P2pPath::RelayFallback,
            Some(0),
            false,
        ));
        assert!(should_retire_non_policy_connection(
            TorMode::Auto,
            P2pPath::RelayFallback,
            Some(0),
            true,
        ));
        assert!(should_retire_non_policy_connection(
            TorMode::RequireTor,
            P2pPath::RelayFallback,
            Some(0),
            false,
        ));
    }

    #[derive(Clone, Default)]
    struct RecordingTransport {
        dialed: Arc<Mutex<Vec<Multiaddr>>>,
        listened: Arc<Mutex<Vec<Multiaddr>>>,
    }

    impl Transport for RecordingTransport {
        type Output = ();
        type Error = io::Error;
        type ListenerUpgrade = Pending<std::result::Result<(), io::Error>>;
        type Dial = Ready<std::result::Result<(), io::Error>>;

        fn listen_on(
            &mut self,
            _id: ListenerId,
            address: Multiaddr,
        ) -> std::result::Result<(), TransportError<Self::Error>> {
            self.listened.lock().unwrap().push(address);
            Ok(())
        }

        fn remove_listener(&mut self, _id: ListenerId) -> bool {
            false
        }

        fn dial(
            &mut self,
            address: Multiaddr,
            _options: TransportDialOpts,
        ) -> std::result::Result<Self::Dial, TransportError<Self::Error>> {
            self.dialed.lock().unwrap().push(address);
            Ok(ready(Ok(())))
        }

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            Poll::Pending
        }
    }

    #[test]
    fn require_tor_blocks_mixed_discovery_dials_at_transport_boundary() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([200; 32]));
        let peer = keys.node_id().libp2p_peer_id().unwrap();
        let ip: Multiaddr = format!("/ip4/192.0.2.1/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relay: Multiaddr =
            format!("/ip4/192.0.2.2/udp/44001/quic-v1/p2p/{peer}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        let onion = onion_listener_address(keys.node_id()).unwrap();
        let mut invalid_onion = onion.clone();
        invalid_onion.push(libp2p::multiaddr::Protocol::P2pCircuit);
        let inner = RecordingTransport::default();
        let dialed = inner.dialed.clone();
        let listened = inner.listened.clone();
        let mut transport = PolicyTransport::new(inner, TorMode::RequireTor);
        let options = TransportDialOpts {
            role: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };

        for forbidden in [ip, relay, invalid_onion] {
            assert!(matches!(
                transport.dial(forbidden, options),
                Err(TransportError::MultiaddrNotSupported(_))
            ));
        }
        assert!(transport.dial(onion.clone(), options).is_ok());
        assert_eq!(*dialed.lock().unwrap(), vec![onion]);

        let forbidden_listener: Multiaddr = "/ip4/0.0.0.0/udp/44000/quic-v1".parse().unwrap();
        assert!(matches!(
            transport.listen_on(ListenerId::next(), forbidden_listener),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
        let onion_listener = onion_listener_address(keys.node_id()).unwrap();
        assert!(
            transport
                .listen_on(ListenerId::next(), onion_listener.clone())
                .is_ok()
        );
        assert_eq!(*listened.lock().unwrap(), vec![onion_listener]);
    }

    #[tokio::test]
    async fn kademlia_originated_dials_cross_the_require_tor_transport_boundary() {
        let local = KeyMaterial::from_seed(&Seed::from_bytes([203; 32]));
        let remote = KeyMaterial::from_seed(&Seed::from_bytes([204; 32]));
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([205; 32]));
        let remote_peer = remote.node_id().libp2p_peer_id().unwrap();
        let relay_peer = relay.node_id().libp2p_peer_id().unwrap();
        let ip: Multiaddr = "/ip4/192.0.2.20/udp/44000/quic-v1".parse().unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.21/udp/44001/quic-v1/p2p/{relay_peer}/p2p-circuit")
                .parse()
                .unwrap();
        let expected = BTreeSet::from([
            ip.clone()
                .with(libp2p::multiaddr::Protocol::P2p(remote_peer)),
            relayed
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(remote_peer)),
        ]);

        let identity = local.libp2p_keypair();
        let local_peer = identity.public().to_peer_id();
        let transport = quic::tokio::Transport::new(quic::Config::new(&identity))
            .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
        let transport = PolicyTransport::new(transport, TorMode::RequireTor);
        let mut swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_other_transport(move |_| transport)
            .unwrap()
            .with_behaviour(move |_| kad::Behaviour::new(local_peer, MemoryStore::new(local_peer)))
            .unwrap()
            .build();
        swarm.behaviour_mut().add_address(&remote_peer, ip.clone());
        swarm
            .behaviour_mut()
            .add_address(&remote_peer, relayed.clone());
        swarm.behaviour_mut().bootstrap().unwrap();

        let rejected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(peer),
                    error: libp2p::swarm::DialError::Transport(errors),
                    ..
                } = swarm.select_next_some().await
                    && peer == remote_peer
                {
                    return errors;
                }
            }
        })
        .await
        .expect("Kademlia did not attempt its mixed forbidden address set");
        assert_eq!(
            rejected
                .into_iter()
                .map(|(address, error)| {
                    assert!(matches!(error, TransportError::MultiaddrNotSupported(_)));
                    address
                })
                .collect::<BTreeSet<_>>(),
            expected
        );
    }

    #[test]
    fn configured_ip_endpoint_does_not_hide_active_onion_listener() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([202; 32]));
        let onion = onion_listener_address(keys.node_id()).unwrap().to_string();
        let direct_listener = "/ip4/0.0.0.0/udp/44000/quic-v1".to_owned();
        let relay_listener = format!(
            "/ip4/192.0.2.2/udp/44001/quic-v1/p2p/{}/p2p-circuit",
            keys.node_id().libp2p_peer_id().unwrap()
        );
        let external: Multiaddr = "/ip4/198.51.100.7/udp/44000/quic-v1".parse().unwrap();
        let mapped: Multiaddr = "/ip4/203.0.113.8/udp/44002/quic-v1".parse().unwrap();
        let advertised = status_advertised_addresses(
            keys.node_id().libp2p_peer_id().unwrap(),
            std::slice::from_ref(&external),
            Some(&mapped),
            &[direct_listener, onion.clone(), relay_listener.clone()],
        );
        let mut expected = vec![
            external.to_string(),
            mapped.to_string(),
            onion,
            relay_listener,
        ];
        expected.sort();
        assert_eq!(advertised.addresses, expected);
        assert!(advertised.rejected.is_empty());
    }

    #[test]
    fn local_endpoint_configuration_is_identity_bound_canonical_and_bounded() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([201; 32]));
        let node_id = keys.node_id();
        let peer = node_id.libp2p_peer_id().unwrap();
        let other = KeyMaterial::from_seed(&Seed::from_bytes([202; 32])).node_id();
        let direct: Multiaddr = format!("/ip4/198.51.100.1/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let canonical = validate_local_advertised_endpoints(
            node_id,
            TorMode::DisableTor,
            &[],
            &[direct.clone(), direct],
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            canonical,
            vec![
                "/ip4/198.51.100.1/udp/44000/quic-v1"
                    .parse::<Multiaddr>()
                    .unwrap()
            ]
        );

        let wrong_peer: Multiaddr = format!(
            "/ip4/198.51.100.2/udp/44000/quic-v1/p2p/{}",
            other.libp2p_peer_id().unwrap()
        )
        .parse()
        .unwrap();
        assert!(
            validate_local_advertised_endpoints(
                node_id,
                TorMode::DisableTor,
                &[],
                &[wrong_peer],
                &[],
                false,
            )
            .is_err()
        );
        assert!(
            validate_local_advertised_endpoints(
                node_id,
                TorMode::Auto,
                &[],
                &[onion_listener_address(other).unwrap()],
                &[],
                false,
            )
            .is_err()
        );
        let configured_circuit: Multiaddr = format!(
            "/ip4/198.51.100.2/udp/44000/quic-v1/p2p/{}/p2p-circuit",
            other.libp2p_peer_id().unwrap()
        )
        .parse()
        .unwrap();
        assert!(
            validate_local_advertised_endpoints(
                node_id,
                TorMode::Auto,
                &[],
                &[configured_circuit],
                &[],
                false,
            )
            .is_err()
        );

        for unusable in [
            "/memory/1",
            "/ip4/198.51.100.3/tcp/44000",
            "/ip4/0.0.0.0/udp/44000/quic-v1",
            "/ip4/198.51.100.3/udp/0/quic-v1",
            "/ip4/224.0.0.1/udp/44000/quic-v1",
            "/ip6/ff02::1/udp/44000/quic-v1",
            "/ip6/fe80::1/udp/44000/quic-v1",
        ] {
            let unusable = unusable.parse::<Multiaddr>().unwrap();
            assert!(
                validate_local_advertised_endpoints(
                    node_id,
                    TorMode::DisableTor,
                    &[],
                    &[unusable],
                    &[],
                    false,
                )
                .is_err()
            );
        }

        let peer_suffix = format!("/p2p/{peer}");
        let dns_prefix = "/dns4/";
        let quic_suffix = "/udp/44000/quic-v1";
        let target_base_len = MAX_ENDPOINT_BYTES - peer_suffix.len() + 1;
        let host_len = target_base_len - dns_prefix.len() - quic_suffix.len();
        let overlong_base = format!("{dns_prefix}{}{quic_suffix}", "a".repeat(host_len));
        assert!(overlong_base.len() <= MAX_ENDPOINT_BYTES);
        assert!(overlong_base.len() + peer_suffix.len() > MAX_ENDPOINT_BYTES);
        let error = validate_published_endpoint(node_id, &format!("{overlong_base}{peer_suffix}"))
            .unwrap_err();
        assert!(error.to_string().contains("too long"));

        let noncanonical = format!("/ip6/0:0:0:0:0:0:0:1/udp/44000/quic-v1/p2p/{peer}");
        assert!(validate_published_endpoint(node_id, &noncanonical).is_err());

        let wildcard: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
        assert!(
            validate_local_advertised_endpoints(
                node_id,
                TorMode::DisableTor,
                std::slice::from_ref(&wildcard),
                &[],
                &[],
                false,
            )
            .is_err(),
            "a wildcard listener alone can never become a signed endpoint"
        );
        validate_local_advertised_endpoints(
            node_id,
            TorMode::DisableTor,
            std::slice::from_ref(&wildcard),
            &[],
            &[],
            true,
        )
        .unwrap();
        validate_local_advertised_endpoints(
            node_id,
            TorMode::DisableTor,
            &["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            &[],
            &[],
            false,
        )
        .unwrap();

        let eight = (0..MAX_ENDPOINTS_PER_PEER)
            .map(|index| {
                format!("/ip4/198.51.100.3/udp/{}/quic-v1", 44000 + index)
                    .parse::<Multiaddr>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        validate_local_advertised_endpoints(node_id, TorMode::Auto, &[], &eight, &[], false)
            .unwrap();
        validate_local_advertised_endpoints(node_id, TorMode::DisableTor, &[], &eight, &[], true)
            .unwrap();
        let mut too_many = eight.clone();
        too_many.push("/ip4/198.51.100.3/udp/45000/quic-v1".parse().unwrap());
        assert!(
            validate_local_advertised_endpoints(
                node_id,
                TorMode::DisableTor,
                &[],
                &too_many,
                &[],
                false,
            )
            .is_err()
        );

        let overflow = status_advertised_addresses(
            peer,
            &[],
            None,
            &(0..MAX_ENDPOINTS_PER_PEER + 3)
                .map(|index| format!("/ip4/203.0.113.1/udp/{}/quic-v1", 45000 + index))
                .collect::<Vec<_>>(),
        );
        assert_eq!(overflow.addresses.len(), MAX_ENDPOINTS_PER_PEER);
        assert!(overflow.addresses.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn runtime_endpoint_selection_preserves_classes_and_rejects_candidates_independently() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([210; 32]));
        let local_peer = keys.node_id().libp2p_peer_id().unwrap();
        let onion = onion_listener_address(keys.node_id()).unwrap().to_string();
        let direct = "/ip4/198.51.100.40/udp/44000/quic-v1".to_owned();
        let mut listeners = vec![
            direct.clone(),
            onion.clone(),
            "/ip4/0.0.0.0/udp/44000/quic-v1".to_owned(),
        ];
        for index in 0_u8..10 {
            let relay_peer = KeyMaterial::from_seed(&Seed::from_bytes([index + 1; 32]))
                .node_id()
                .libp2p_peer_id()
                .unwrap();
            listeners.push(format!(
                "/ip4/192.0.2.{}/udp/{}/quic-v1/p2p/{relay_peer}/p2p-circuit",
                index + 1,
                45000 + u16::from(index)
            ));
        }

        let selected = status_advertised_addresses(local_peer, &[], None, &listeners);
        assert_eq!(selected.addresses.len(), MAX_ENDPOINTS_PER_PEER);
        assert!(selected.addresses.contains(&onion));
        assert!(selected.addresses.contains(&direct));
        assert!(
            selected
                .addresses
                .iter()
                .any(|address| address.contains("/p2p-circuit"))
        );
        assert_eq!(selected.rejected.len(), 1);
        assert!(selected.rejected[0].contains("0.0.0.0"));
    }

    #[test]
    fn bootstrap_addresses_are_canonical_bounded_supported_and_policy_compatible() -> Result<()> {
        let destination = KeyMaterial::from_seed(&Seed::from_bytes([211; 32]));
        let destination_peer = destination.node_id().libp2p_peer_id().unwrap();
        let relay_peer = KeyMaterial::from_seed(&Seed::from_bytes([212; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let direct = format!("/ip4/198.51.100.10/udp/44000/quic-v1/p2p/{destination_peer}");
        let circuit = format!(
            "/ip4/198.51.100.11/udp/44001/quic-v1/p2p/{relay_peer}/p2p-circuit/p2p/{destination_peer}"
        );
        let onion = onion_listener_address(destination.node_id())?
            .with(libp2p::multiaddr::Protocol::P2p(destination_peer))
            .to_string();

        assert_eq!(
            validate_bootstrap_addresses(
                TorMode::Auto,
                &[direct.clone(), circuit.clone(), onion.clone()]
            )?
            .len(),
            3
        );
        for invalid in [
            "/ip4/198.51.100.10/udp/44000/quic-v1".to_owned(),
            format!("/ip4/198.51.100.10/p2p/{destination_peer}/udp/44000/quic-v1"),
            format!("/ip4/0.0.0.0/udp/44000/quic-v1/p2p/{destination_peer}"),
            format!("/ip4/198.51.100.10/udp/0/quic-v1/p2p/{destination_peer}"),
            format!("/ip4/198.51.100.10/tcp/44000/p2p/{destination_peer}"),
            format!("/ip6/0:0:0:0:0:0:0:1/udp/44000/quic-v1/p2p/{destination_peer}"),
        ] {
            assert!(
                validate_bootstrap_addresses(TorMode::Auto, &[invalid.clone()]).is_err(),
                "accepted {invalid}"
            );
        }

        let wrong_onion = onion_listener_address(destination.node_id())?
            .with(libp2p::multiaddr::Protocol::P2p(relay_peer))
            .to_string();
        assert!(validate_bootstrap_addresses(TorMode::Auto, &[wrong_onion]).is_err());
        assert!(validate_bootstrap_addresses(TorMode::RequireTor, &[direct.clone()]).is_err());
        assert!(validate_bootstrap_addresses(TorMode::DisableTor, &[onion]).is_err());
        assert!(
            validate_bootstrap_addresses(TorMode::Auto, &vec![direct; MAX_BOOTSTRAP_ADDRESSES + 1])
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn publication_rejects_one_bad_runtime_candidate_without_suppressing_valid_ones() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([204; 32]);
        let node_id = KeyMaterial::from_seed(&seed).node_id();
        let node = Node::open(temp.path().join("node"), seed).unwrap();
        let (client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(node_id)).unwrap();
        event_loop.advertised_addresses = vec![
            "/ip4/198.51.100.8/udp/44000/quic-v1".parse().unwrap(),
            "/ip4/198.51.100.9/udp/0/quic-v1".parse().unwrap(),
        ];
        let task = tokio::spawn(event_loop.run());

        let endpoints = available_p2p_endpoints(&client).await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].contains("198.51.100.8"));
        assert!(
            client
                .status()
                .await
                .unwrap()
                .degraded
                .iter()
                .any(|reason| reason.contains("198.51.100.9"))
        );

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mapped_external_address_is_replaceable_and_controls_degraded_status() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([203; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let node = Node::open(temp.path().join("node"), seed).unwrap();
        let mut p2p_config = config(keys.node_id());
        p2p_config.listen_addresses = vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()];
        p2p_config.enable_port_mapping = true;
        let (_, mut event_loop) = build_p2p(Arc::new(Mutex::new(node)), p2p_config).unwrap();

        assert!(
            event_loop
                .transport_degradation()
                .iter()
                .any(|reason| reason.contains("port mapping"))
        );
        event_loop.port_mapping_listener_active = true;
        let first: Multiaddr = "/ip4/198.51.100.8/udp/44000/quic-v1".parse().unwrap();
        event_loop
            .replace_mapped_external_address(Some(first.clone()))
            .unwrap();
        assert_eq!(event_loop.mapped_external_address.as_ref(), Some(&first));
        assert!(
            !event_loop
                .transport_degradation()
                .iter()
                .any(|reason| reason.contains("port mapping"))
        );

        let second: Multiaddr = "/ip4/203.0.113.9/udp/44001/quic-v1".parse().unwrap();
        event_loop
            .replace_mapped_external_address(Some(second.clone()))
            .unwrap();
        assert_eq!(event_loop.mapped_external_address.as_ref(), Some(&second));
        event_loop.replace_mapped_external_address(None).unwrap();
        assert!(event_loop.mapped_external_address.is_none());
        assert!(
            event_loop
                .transport_degradation()
                .iter()
                .any(|reason| reason.contains("port mapping"))
        );
    }

    #[tokio::test]
    async fn mapped_listener_close_withdraws_the_endpoint_before_mapper_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([213; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let node = Node::open(temp.path().join("node"), seed).unwrap();
        let mut p2p_config = config(keys.node_id());
        p2p_config.listen_addresses = vec![
            "/ip4/0.0.0.0/udp/44000/quic-v1".parse().unwrap(),
            "/ip6/::1/udp/44001/quic-v1".parse().unwrap(),
        ];
        p2p_config.enable_port_mapping = true;
        let (client, mut event_loop) = build_p2p(Arc::new(Mutex::new(node)), p2p_config).unwrap();
        let listener = event_loop.port_mapping_listener.unwrap();
        let port = NonZeroU16::new(44000).unwrap();
        event_loop.port_mapping_listener_active = true;
        event_loop
            .port_mapping_listener_state
            .send_replace(PortMappingListenerState::Active(port));
        let mapped: Multiaddr = "/ip4/198.51.100.8/udp/44000/quic-v1".parse().unwrap();
        event_loop
            .replace_mapped_external_address(Some(mapped.clone()))
            .unwrap();
        let mut listener_state = client.port_mapping_listener_state();

        event_loop.observe_port_mapping_listener_closed(listener);

        assert!(event_loop.mapped_external_address.is_none());
        assert_eq!(
            *listener_state.borrow_and_update(),
            PortMappingListenerState::Closed
        );
        assert!(
            event_loop
                .replace_mapped_external_address(Some(mapped))
                .is_err(),
            "a late mapper update must not revive the closed listener endpoint"
        );
        assert!(event_loop.fatal_error.is_none());
    }

    const LEGACY_MEMBER_POISON_SEQUENCE: u64 = u64::MAX - 1;

    fn install_legacy_recovery_observation_poison(
        data_dir: &std::path::Path,
        subject_seed: &Seed,
        authorized_publisher_seed: &Seed,
    ) {
        #[derive(serde::Serialize)]
        struct StoredHash {
            sequence: u64,
            hash: [u8; 32],
        }

        #[derive(serde::Serialize)]
        struct StoredRecord {
            sequence: u64,
            hash: [u8; 32],
            expires_at_unix_seconds: u64,
            bytes: Vec<u8>,
        }

        #[derive(serde::Serialize)]
        struct StoredState {
            format_version: u16,
            highest_sequence: u64,
            hashes: Vec<StoredHash>,
            current: StoredRecord,
        }

        std::fs::create_dir_all(data_dir).unwrap();
        let subject_keys = KeyMaterial::from_seed(subject_seed);
        let subject = subject_keys.node_id();
        let control =
            mb_store::ControlStore::open(data_dir.join("control.db"), &subject_keys).unwrap();
        let now = unix_seconds();
        for index in 0_u8..63 {
            let mut fake_seed = [0xe7; 32];
            fake_seed[0] = index;
            fake_seed[31] = !index;
            let publisher_keys = KeyMaterial::from_seed(&Seed::from_bytes(fake_seed));
            let publisher = publisher_keys.node_id();
            let provider = publisher.libp2p_peer_id().unwrap().to_string();
            let expires_at_unix_seconds = if index < 32 {
                now.saturating_sub(1)
            } else {
                now + 300
            };
            let bundle = SignedRecord::sign(
                b"mutualbackup/recovery-bundle/v1",
                mb_core::RecoveryBundle {
                    format_version: 1,
                    subject,
                    publisher,
                    sequence: 1,
                    expires_at_unix_seconds,
                    sealed: mb_core::SealedRecoveryRecord {
                        format_version: 1,
                        ephemeral_public_key: [index.wrapping_add(1); 32],
                        nonce: [index.wrapping_add(1); 24],
                        ciphertext: vec![index; 64],
                    },
                },
                &publisher_keys,
            )
            .unwrap();
            let bytes = canonical_bytes(&bundle).unwrap();
            let hash = *blake3::hash(&bytes).as_bytes();
            let state = StoredState {
                format_version: 1,
                highest_sequence: 1,
                hashes: vec![StoredHash { sequence: 1, hash }],
                current: StoredRecord {
                    sequence: 1,
                    hash,
                    expires_at_unix_seconds,
                    bytes,
                },
            };
            let mut record_id = [0_u8; 64];
            record_id[..32].copy_from_slice(&subject.0);
            record_id[32..].copy_from_slice(blake3::hash(provider.as_bytes()).as_bytes());
            control
                .put_record(
                    "dht-observed-recovery",
                    &record_id,
                    &canonical_bytes(&state).unwrap(),
                )
                .unwrap();
        }
        let publisher_keys = KeyMaterial::from_seed(authorized_publisher_seed);
        let publisher = publisher_keys.node_id();
        let provider = publisher.libp2p_peer_id().unwrap().to_string();
        let expires_at_unix_seconds = now + 300;
        let bundle = SignedRecord::sign(
            b"mutualbackup/recovery-bundle/v1",
            mb_core::RecoveryBundle {
                format_version: 1,
                subject,
                publisher,
                sequence: LEGACY_MEMBER_POISON_SEQUENCE,
                expires_at_unix_seconds,
                sealed: mb_core::SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [0; 32],
                    nonce: [0; 24],
                    ciphertext: vec![0; 64],
                },
            },
            &publisher_keys,
        )
        .unwrap();
        let bytes = canonical_bytes(&bundle).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        let state = StoredState {
            format_version: 1,
            highest_sequence: LEGACY_MEMBER_POISON_SEQUENCE,
            hashes: vec![StoredHash {
                sequence: LEGACY_MEMBER_POISON_SEQUENCE,
                hash,
            }],
            current: StoredRecord {
                sequence: LEGACY_MEMBER_POISON_SEQUENCE,
                hash,
                expires_at_unix_seconds,
                bytes,
            },
        };
        let mut record_id = [0_u8; 64];
        record_id[..32].copy_from_slice(&subject.0);
        record_id[32..].copy_from_slice(blake3::hash(provider.as_bytes()).as_bytes());
        control
            .put_record(
                "dht-observed-recovery",
                &record_id,
                &canonical_bytes(&state).unwrap(),
            )
            .unwrap();
        assert_eq!(control.records("dht-observed-recovery").unwrap().len(), 64);
    }

    #[tokio::test]
    async fn abandoned_callers_cannot_evade_the_dispatched_request_bound() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([79; 32]));
        let node = Arc::new(Mutex::new(
            Node::open(temp.path().join("node"), Seed::from_bytes([79; 32])).unwrap(),
        ));
        let mut p2p_config = config(keys.node_id());
        p2p_config.max_connections = 2;
        let (client, mut event_loop) = build_p2p(node, p2p_config).unwrap();
        let peer = KeyMaterial::from_seed(&Seed::from_bytes([80; 32])).node_id();
        let peer_id = peer.libp2p_peer_id().unwrap();
        event_loop
            .connection_paths
            .insert(ConnectionId::new_unchecked(780), (peer_id, P2pPath::Direct));

        let started = tokio::spawn({
            let client = client.clone();
            async move { client.call(peer, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        assert_eq!(event_loop.pending_requests.len(), 1);
        assert_eq!(client.outbound_permits.available_permits(), 1);

        started.abort();
        assert!(started.await.unwrap_err().is_cancelled());
        let cancellation_id = tokio::time::timeout(
            Duration::from_secs(1),
            event_loop.request_cancellations.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        event_loop.cancel_request(cancellation_id);
        assert_eq!(event_loop.pending_requests.len(), 1);
        assert_eq!(client.outbound_permits.available_permits(), 1);

        let queued = tokio::spawn({
            let client = client.clone();
            async move { client.call(peer, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        let cancellation_id = tokio::time::timeout(
            Duration::from_secs(1),
            event_loop.request_cancellations.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        event_loop.cancel_request(cancellation_id);
        event_loop.handle_command(command).unwrap();
        assert_eq!(event_loop.pending_requests.len(), 1);
        assert!(event_loop.queued_requests.is_empty());
        assert_eq!(client.outbound_permits.available_permits(), 1);

        drop(event_loop);
        assert_eq!(client.outbound_permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn a_retirement_without_a_close_event_resumes_queued_requests() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([84; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        let target = KeyMaterial::from_seed(&Seed::from_bytes([85; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let address: Multiaddr = format!("/ip4/192.0.2.85/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        event_loop.add_learned_address(peer, address).unwrap();

        let retiring = ConnectionId::new_unchecked(799);
        event_loop
            .connection_paths
            .insert(retiring, (peer, P2pPath::Direct));
        event_loop.duplicate_retirement.insert(
            retiring,
            (peer, tokio::time::Instant::now() - Duration::from_secs(1)),
        );
        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        assert!(event_loop.pending_requests.is_empty());
        assert_eq!(event_loop.queued_requests.len(), 1);

        event_loop.retire_duplicate_sessions();
        assert!(event_loop.duplicate_retirement.is_empty());
        assert!(event_loop.queued_requests.is_empty());
        assert_eq!(event_loop.pending_requests.len(), 1);

        drop(event_loop);
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn duplicate_collapse_preserves_the_connection_owning_a_relay_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([86; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([87; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let relay_address: Multiaddr = format!("/ip4/192.0.2.87/udp/44000/quic-v1/p2p/{relay}")
            .parse()
            .unwrap();
        let mut p2p_config = config(local_id);
        p2p_config.relay_reservation_addresses = vec![relay_address];
        let (_client, mut event_loop) = build_p2p(
            Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap())),
            p2p_config,
        )
        .unwrap();

        let reservation_connection = ConnectionId::new_unchecked(801);
        let inbound_duplicate = ConnectionId::new_unchecked(802);
        event_loop
            .connection_paths
            .insert(reservation_connection, (relay, P2pPath::Direct));
        event_loop
            .connection_dialers
            .insert(reservation_connection, true);
        event_loop
            .connection_paths
            .insert(inbound_duplicate, (relay, P2pPath::Direct));
        event_loop
            .connection_dialers
            .insert(inbound_duplicate, false);

        event_loop.schedule_duplicate_session_collapse(relay, inbound_duplicate);

        assert!(event_loop.duplicate_retirement.is_empty());
    }

    #[tokio::test]
    async fn retiring_and_unhealthy_connections_are_not_collapse_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([88; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let peer = KeyMaterial::from_seed(&Seed::from_bytes([89; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let (_client, mut event_loop) = build_p2p(
            Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap())),
            config(local_id),
        )
        .unwrap();
        let retiring = ConnectionId::new_unchecked(811);
        let candidate = ConnectionId::new_unchecked(812);
        event_loop
            .connection_paths
            .insert(retiring, (peer, P2pPath::RelayFallback));
        event_loop
            .connection_paths
            .insert(candidate, (peer, P2pPath::HolePunched));

        assert!(event_loop.healthy_path_exists(peer, P2pPath::HolePunched));
        assert!(event_loop.healthy_replacement_exists(
            peer,
            retiring,
            path_preference_rank(event_loop.tor_mode, P2pPath::RelayFallback),
        ));

        event_loop.duplicate_retirement.insert(
            candidate,
            (peer, tokio::time::Instant::now() + Duration::from_secs(1)),
        );
        assert!(!event_loop.healthy_path_exists(peer, P2pPath::HolePunched));
        assert!(!event_loop.healthy_replacement_exists(
            peer,
            retiring,
            path_preference_rank(event_loop.tor_mode, P2pPath::RelayFallback),
        ));

        event_loop.duplicate_retirement.remove(&candidate);
        event_loop.unhealthy_connections.insert(candidate);
        assert!(!event_loop.healthy_path_exists(peer, P2pPath::HolePunched));
        assert!(!event_loop.healthy_replacement_exists(
            peer,
            retiring,
            path_preference_rank(event_loop.tor_mode, P2pPath::RelayFallback),
        ));
    }

    #[tokio::test]
    async fn request_failure_uses_healthy_duplicate_then_advances_each_transport_once() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([81; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        // This is a synthetic event-state test and does not poll the concrete
        // transport. Keep construction cheap, then exercise the exact Auto
        // policy state that includes all three tiers.
        event_loop.tor_mode = TorMode::Auto;
        let target_keys = KeyMaterial::from_seed(&Seed::from_bytes([82; 32]));
        let target = target_keys.node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([83; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.10/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.11/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        let onion = onion_listener_address(target).unwrap();
        for address in [direct, relayed, onion] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        let healthy_direct = ConnectionId::new_unchecked(800);
        event_loop
            .connection_paths
            .insert(healthy_direct, (peer, P2pPath::Direct));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        let first_outbound = *event_loop.pending_requests.keys().next().unwrap();
        let signed_request =
            canonical_bytes(&event_loop.pending_requests[&first_outbound].request).unwrap();
        let protocol_request_id = event_loop.pending_requests[&first_outbound].request_id;

        // A connection-selection race onto a non-selected tier is quarantined
        // and retried at the original tier rather than skipping a fallback.
        let wrong_tier = ConnectionId::new_unchecked(801);
        event_loop.remember_closed_connection_path(wrong_tier, peer, P2pPath::RelayFallback);
        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: wrong_tier,
            request_id: first_outbound,
            error: request_response::OutboundFailure::Timeout,
        });
        assert_eq!(
            event_loop.fallback_tiers.get(&peer).copied().unwrap_or(0),
            0
        );
        let after_wrong_tier = *event_loop.pending_requests.keys().next().unwrap();
        assert_eq!(
            canonical_bytes(&event_loop.pending_requests[&after_wrong_tier].request).unwrap(),
            signed_request
        );

        let failed = ConnectionId::new_unchecked(802);
        event_loop.remember_closed_connection_path(failed, peer, P2pPath::Direct);
        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: failed,
            request_id: after_wrong_tier,
            error: request_response::OutboundFailure::Timeout,
        });
        assert_eq!(
            event_loop.fallback_tiers.get(&peer).copied().unwrap_or(0),
            0
        );
        assert_eq!(event_loop.pending_requests.len(), 1);
        let second_outbound = *event_loop.pending_requests.keys().next().unwrap();
        assert_eq!(
            canonical_bytes(&event_loop.pending_requests[&second_outbound].request).unwrap(),
            signed_request
        );
        assert_eq!(
            event_loop.pending_requests[&second_outbound].request_id,
            protocol_request_id
        );

        event_loop.connection_paths.remove(&healthy_direct);
        let direct_failure = ConnectionId::new_unchecked(803);
        event_loop.remember_closed_connection_path(direct_failure, peer, P2pPath::Direct);
        let healthy_relay = ConnectionId::new_unchecked(804);
        event_loop
            .connection_paths
            .insert(healthy_relay, (peer, P2pPath::RelayFallback));
        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: direct_failure,
            request_id: second_outbound,
            error: request_response::OutboundFailure::Timeout,
        });
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&1));
        let third_outbound = *event_loop.pending_requests.keys().next().unwrap();
        assert_eq!(
            canonical_bytes(&event_loop.pending_requests[&third_outbound].request).unwrap(),
            signed_request
        );

        event_loop.connection_paths.remove(&healthy_relay);
        let relay_failure = ConnectionId::new_unchecked(805);
        event_loop.remember_closed_connection_path(relay_failure, peer, P2pPath::RelayFallback);
        let healthy_tor = ConnectionId::new_unchecked(806);
        event_loop
            .connection_paths
            .insert(healthy_tor, (peer, P2pPath::Tor));
        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: relay_failure,
            request_id: third_outbound,
            error: request_response::OutboundFailure::Timeout,
        });
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&2));
        let fourth_outbound = *event_loop.pending_requests.keys().next().unwrap();
        assert_eq!(
            canonical_bytes(&event_loop.pending_requests[&fourth_outbound].request).unwrap(),
            signed_request
        );
        assert_eq!(event_loop.pending_requests[&fourth_outbound].attempts, 5);

        event_loop.connection_paths.remove(&healthy_tor);
        let tor_failure = ConnectionId::new_unchecked(807);
        event_loop.remember_closed_connection_path(tor_failure, peer, P2pPath::Tor);
        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: tor_failure,
            request_id: fourth_outbound,
            error: request_response::OutboundFailure::Timeout,
        });
        assert!(event_loop.pending_requests.is_empty());
        assert!(call.await.unwrap().is_err());
        assert_eq!(client.outbound_permits.available_permits(), 8);
    }

    #[tokio::test]
    async fn prefer_tor_does_not_dispatch_on_a_retained_direct_connection() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([90; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::PreferTor;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([91; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.90/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        for address in [direct, onion_listener_address(target).unwrap()] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        event_loop.set_transport_tier(peer, 0);
        let direct_connection = ConnectionId::new_unchecked(901);
        event_loop
            .connection_paths
            .insert(direct_connection, (peer, P2pPath::Direct));
        event_loop.observe_established_transport(peer, direct_connection);

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();

        assert!(event_loop.pending_requests.is_empty());
        assert_eq!(event_loop.queued_requests.len(), 1);
        assert!(event_loop.policy_dials.values().any(|dial| {
            dial.peer == peer && dial.tier == 0 && dial.kind == PolicyDialKind::Selected
        }));

        drop(event_loop);
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn fallback_dials_advance_in_order_despite_a_retained_worse_connection() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([92; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::Auto;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([93; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([94; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.92/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.93/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        for address in [direct, relayed, onion_listener_address(target).unwrap()] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        event_loop
            .connection_paths
            .insert(ConnectionId::new_unchecked(921), (peer, P2pPath::Tor));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        assert_eq!(event_loop.queued_requests.len(), 1);
        let direct_dial = event_loop
            .policy_dials
            .iter()
            .find_map(|(connection, dial)| {
                (dial.peer == peer && dial.tier == 0).then_some(*connection)
            })
            .unwrap();

        event_loop.handle_swarm_event(SwarmEvent::OutgoingConnectionError {
            connection_id: direct_dial,
            peer_id: Some(peer),
            error: libp2p::swarm::DialError::Aborted,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert_eq!(event_loop.queued_requests.len(), 1);
        let relay_dial = event_loop
            .policy_dials
            .iter()
            .find_map(|(connection, dial)| {
                (dial.peer == peer && dial.tier == 1).then_some(*connection)
            })
            .unwrap();

        let stale_direct_dial = ConnectionId::new_unchecked(922);
        event_loop.policy_dials.insert(
            stale_direct_dial,
            PolicyDial {
                peer,
                tier: 0,
                path: P2pPath::Direct,
                kind: PolicyDialKind::Selected,
            },
        );
        event_loop.handle_swarm_event(SwarmEvent::OutgoingConnectionError {
            connection_id: stale_direct_dial,
            peer_id: Some(peer),
            error: libp2p::swarm::DialError::Aborted,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert!(event_loop.policy_dials.contains_key(&relay_dial));

        event_loop.handle_swarm_event(SwarmEvent::OutgoingConnectionError {
            connection_id: relay_dial,
            peer_id: Some(peer),
            error: libp2p::swarm::DialError::Aborted,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 2);
        assert!(event_loop.queued_requests.is_empty());
        assert_eq!(event_loop.pending_requests.len(), 1);

        drop(event_loop);
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn closed_connection_path_survives_until_outbound_failure() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([95; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        let target = KeyMaterial::from_seed(&Seed::from_bytes([96; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([97; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.95/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.96/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        for address in [direct.clone(), relayed] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        let connection = ConnectionId::new_unchecked(951);
        event_loop
            .connection_paths
            .insert(connection, (peer, P2pPath::Direct));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        let request_id = *event_loop.pending_requests.keys().next().unwrap();

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint: ConnectedPoint::Dialer {
                address: direct,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: 0,
            cause: None,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert!(event_loop.closed_connection_paths.contains_key(&connection));

        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: connection,
            request_id,
            error: request_response::OutboundFailure::ConnectionClosed,
        });
        assert_eq!(event_loop.path_metrics[&P2pPath::Direct].requests_failed, 1);
        assert_eq!(
            event_loop
                .path_metrics
                .get(&P2pPath::RelayFallback)
                .map_or(0, |metrics| metrics.requests_failed),
            0
        );
        assert!(event_loop.pending_requests.is_empty());
        assert_eq!(event_loop.queued_requests.len(), 1);

        drop(event_loop);
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn selected_close_reuses_same_tier_duplicate_before_request_failure() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([106; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        let target = KeyMaterial::from_seed(&Seed::from_bytes([107; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([108; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.106/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.107/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        for address in [direct.clone(), relayed] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        let selected = ConnectionId::new_unchecked(1061);
        let duplicate = ConnectionId::new_unchecked(1062);
        event_loop
            .connection_paths
            .insert(selected, (peer, P2pPath::Direct));
        event_loop
            .connection_paths
            .insert(duplicate, (peer, P2pPath::Direct));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        let request_id = *event_loop.pending_requests.keys().next().unwrap();
        event_loop.duplicate_retirement.insert(
            duplicate,
            (peer, tokio::time::Instant::now() + Duration::from_secs(1)),
        );

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: selected,
            endpoint: ConnectedPoint::Dialer {
                address: direct,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: 1,
            cause: None,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 0);
        assert!(event_loop.healthy_connection_at_tier(peer, 0, None));
        assert!(!event_loop.duplicate_retirement.contains_key(&duplicate));
        assert!(event_loop.policy_dials.values().all(|dial| dial.tier == 0));

        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: selected,
            request_id,
            error: request_response::OutboundFailure::ConnectionClosed,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 0);
        assert_eq!(event_loop.pending_requests.len(), 1);
        assert!(event_loop.queued_requests.is_empty());

        drop(event_loop);
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn failed_preferred_promotion_keeps_the_retained_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([98; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (_client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        let target = KeyMaterial::from_seed(&Seed::from_bytes([99; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let direct: Multiaddr = format!("/ip4/192.0.2.98/udp/44000/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([100; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.99/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        for address in [direct.clone(), relayed] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        event_loop.set_transport_tier(peer, 1);
        let relay_connection = ConnectionId::new_unchecked(981);
        let direct_connection = ConnectionId::new_unchecked(982);
        event_loop
            .connection_paths
            .insert(relay_connection, (peer, P2pPath::RelayFallback));
        event_loop
            .connection_paths
            .insert(direct_connection, (peer, P2pPath::Direct));
        event_loop.observe_established_transport(peer, direct_connection);

        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert_eq!(event_loop.transport_promotions[&peer].tier, 0);
        assert!(
            !event_loop
                .duplicate_retirement
                .contains_key(&direct_connection)
        );

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: direct_connection,
            endpoint: ConnectedPoint::Dialer {
                address: direct,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: 1,
            cause: None,
        });
        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert!(!event_loop.transport_promotions.contains_key(&peer));
        assert!(event_loop.healthy_connection_at_tier(peer, 1, None));

        event_loop.retry_preferred_paths();
        assert!(event_loop.policy_dials.values().any(|dial| {
            dial.peer == peer && dial.tier == 0 && dial.kind == PolicyDialKind::PreferredProbe
        }));
    }

    #[tokio::test]
    async fn selected_fallback_close_adopts_an_established_preferred_probe() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([103; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (_client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::Auto;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([104; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let relay = KeyMaterial::from_seed(&Seed::from_bytes([105; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let relayed: Multiaddr =
            format!("/ip4/192.0.2.104/udp/44001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        for address in [relayed, onion_listener_address(target).unwrap()] {
            event_loop.add_learned_address(peer, address).unwrap();
        }
        event_loop.set_transport_tier(peer, 2);
        let relay_connection = ConnectionId::new_unchecked(1031);
        event_loop
            .connection_paths
            .insert(relay_connection, (peer, P2pPath::RelayFallback));
        event_loop.duplicate_retirement.insert(
            relay_connection,
            (peer, tokio::time::Instant::now() + Duration::from_secs(1)),
        );

        event_loop.restore_selected_transport_after_close(peer, Some(P2pPath::Tor));

        assert_eq!(event_loop.selected_transport_tier(peer), 1);
        assert!(event_loop.healthy_connection_at_tier(peer, 1, None));
        assert!(
            !event_loop
                .duplicate_retirement
                .contains_key(&relay_connection)
        );
    }

    #[tokio::test]
    async fn logical_request_attempt_budget_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([101; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        let target = KeyMaterial::from_seed(&Seed::from_bytes([102; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        event_loop
            .connection_paths
            .insert(ConnectionId::new_unchecked(1001), (peer, P2pPath::Direct));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        let request_id = *event_loop.pending_requests.keys().next().unwrap();
        let mut pending = event_loop.pending_requests.remove(&request_id).unwrap();
        pending.attempts = MAX_REQUEST_TRANSPORT_ATTEMPTS;
        event_loop.queue_or_dispatch_request(pending);

        let error = call.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("transport attempt budget"));
        assert!(event_loop.pending_requests.is_empty());
        assert!(event_loop.queued_requests.is_empty());
        assert_eq!(client.outbound_permits.available_permits(), 8);
    }

    #[tokio::test]
    async fn recovery_accumulates_shards_across_alternating_availability_and_restart() {
        fn group_for(
            guild_id: [u8; 32],
            local_id: NodeId,
            other_ids: [NodeId; 4],
            byte: u8,
        ) -> (CodingGroup, Vec<u8>) {
            let information = [
                vec![byte; V1_SECTOR_SIZE],
                vec![byte.wrapping_add(1); V1_SECTOR_SIZE],
                vec![byte.wrapping_add(2); V1_SECTOR_SIZE],
            ];
            let shards = encode_3_2(information.clone()).unwrap();
            let roles = [
                ShardRole::Information(InformationRole {
                    owner: other_ids[0],
                    sector: SectorRef {
                        id: [byte; 32],
                        root: sector_root(&information[0]),
                        logical_len: V1_SECTOR_SIZE as u32,
                    },
                }),
                ShardRole::Information(InformationRole {
                    owner: other_ids[1],
                    sector: SectorRef {
                        id: [byte.wrapping_add(1); 32],
                        root: sector_root(&information[1]),
                        logical_len: V1_SECTOR_SIZE as u32,
                    },
                }),
                ShardRole::Information(InformationRole {
                    owner: other_ids[2],
                    sector: SectorRef {
                        id: [byte.wrapping_add(2); 32],
                        root: sector_root(&information[2]),
                        logical_len: V1_SECTOR_SIZE as u32,
                    },
                }),
                ShardRole::Parity(ParityRole {
                    holder: local_id,
                    row: 0,
                    root: sector_root(&shards[3]),
                }),
                ShardRole::Parity(ParityRole {
                    holder: other_ids[3],
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
            group.id = group.calculate_id().unwrap();
            (group, shards[3].clone())
        }

        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([120; 32]);
        let local_id = mb_core::KeyMaterial::from_seed(&seed).node_id();
        let other_ids = [121_u8, 122, 123, 124]
            .map(|value| mb_core::KeyMaterial::from_seed(&Seed::from_bytes([value; 32])).node_id());
        let guild_id = [125; 32];
        let (first_group, first_bytes) = group_for(guild_id, local_id, other_ids, 31);
        let (second_group, second_bytes) = group_for(guild_id, local_id, other_ids, 47);
        let checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 1,
                guild_id,
                genesis_hash: [126; 32],
                generation: 1,
                parent: None,
                members: Vec::new(),
                revisions: Vec::new(),
                coding_groups: vec![first_group.clone(), second_group.clone()],
            },
            signatures: Vec::new(),
        };
        let checkpoint_hash = checkpoint.hash().unwrap();

        let node = Arc::new(Mutex::new(Node::open(temp.path(), seed.clone()).unwrap()));
        let first_id = first_group.id;
        let first_window =
            recover_local_shards_with(node.clone(), &checkpoint, move |group, index| {
                assert_eq!(index, 3);
                std::future::ready(if group.id == first_id {
                    Ok(first_bytes.clone())
                } else {
                    Err(anyhow::anyhow!("second coding group is unavailable"))
                })
            })
            .await;
        assert!(first_window.is_err());
        assert!(
            node.lock()
                .unwrap()
                .recovered_shard_is_staged(&checkpoint_hash, &guild_id, &first_group, 3)
                .unwrap()
        );
        assert!(
            !node
                .lock()
                .unwrap()
                .recovered_shard_is_staged(&checkpoint_hash, &guild_id, &second_group, 3)
                .unwrap()
        );

        drop(node);
        let reopened = Arc::new(Mutex::new(Node::open(temp.path(), seed).unwrap()));
        let second_id = second_group.id;
        recover_local_shards_with(reopened.clone(), &checkpoint, move |group, index| {
            assert_eq!(index, 3);
            assert_eq!(
                group.id, second_id,
                "the durable first shard was fetched again"
            );
            std::future::ready(Ok(second_bytes.clone()))
        })
        .await
        .unwrap();
        for group in [&first_group, &second_group] {
            assert!(
                reopened
                    .lock()
                    .unwrap()
                    .recovered_shard_is_staged(&checkpoint_hash, &guild_id, group, 3)
                    .unwrap()
            );
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
            merge_established_path(Some(P2pPath::HolePunched), P2pPath::Direct),
            P2pPath::HolePunched
        );
        assert_eq!(
            merge_established_path(Some(P2pPath::Relayed), P2pPath::Direct),
            P2pPath::Direct,
        );
    }

    #[tokio::test]
    async fn failed_dcutr_updates_active_history_metrics_and_transfer_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([64; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        let peer = KeyMaterial::from_seed(&Seed::from_bytes([65; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let connection = ConnectionId::new_unchecked(700);
        event_loop
            .persistent_addresses
            .insert(peer, BTreeSet::new());
        event_loop
            .connection_paths
            .insert(connection, (peer, P2pPath::Relayed));
        event_loop.record_session_open(
            connection,
            peer,
            P2pPath::Relayed,
            P2pSessionDirection::Outbound,
        );
        event_loop.record_transfer(peer, Some(P2pPath::Relayed), 10, 20);

        event_loop.classify_failed_dcutr(peer);
        event_loop
            .last_application_paths
            .insert(peer, P2pPath::RelayFallback);
        event_loop.record_transfer(peer, Some(P2pPath::RelayFallback), 30, 40);

        let (response, receiver) = oneshot::channel();
        event_loop
            .handle_command(Command::Status { response })
            .unwrap();
        let status = receiver.await.unwrap();
        let peer_status = status
            .peers
            .iter()
            .find(|status| status.peer_id == peer.to_string())
            .unwrap();
        assert_eq!(peer_status.active_paths, vec![P2pPath::RelayFallback]);
        assert_eq!(
            peer_status.last_application_path,
            Some(P2pPath::RelayFallback)
        );
        assert_eq!(status.active_sessions[0].path, P2pPath::RelayFallback);
        assert_eq!(
            peer_status.path_transfers,
            vec![
                P2pPathTransfer {
                    path: P2pPath::Relayed,
                    application_bytes_sent: 10,
                    application_bytes_received: 20,
                },
                P2pPathTransfer {
                    path: P2pPath::RelayFallback,
                    application_bytes_sent: 30,
                    application_bytes_received: 40,
                },
            ]
        );

        event_loop.connection_paths.remove(&connection);
        event_loop.record_session_close(connection, false);
        assert_eq!(
            event_loop.recent_sessions.back().unwrap().path,
            P2pPath::RelayFallback
        );
        assert_eq!(
            event_loop.path_metrics[&P2pPath::Relayed].sessions_opened,
            0
        );
        assert_eq!(
            event_loop.path_metrics[&P2pPath::RelayFallback].sessions_opened,
            1
        );
        assert_eq!(
            event_loop.path_metrics[&P2pPath::RelayFallback].sessions_closed,
            1
        );
        assert_eq!(
            event_loop.path_metrics[&P2pPath::Relayed].application_bytes_sent,
            10
        );
        assert_eq!(
            event_loop.path_metrics[&P2pPath::RelayFallback].application_bytes_sent,
            30
        );
    }

    #[tokio::test]
    async fn an_unhealthy_session_closed_locally_is_recorded_as_a_transport_error() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([62; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        let peer = KeyMaterial::from_seed(&Seed::from_bytes([63; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let connection = ConnectionId::new_unchecked(701);
        let address: Multiaddr = "/ip4/192.0.2.63/udp/44000/quic-v1".parse().unwrap();
        let endpoint = ConnectedPoint::Dialer {
            address,
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        event_loop
            .connection_paths
            .insert(connection, (peer, P2pPath::Direct));
        event_loop.record_session_open(
            connection,
            peer,
            P2pPath::Direct,
            P2pSessionDirection::Outbound,
        );
        event_loop.unhealthy_connections.insert(connection);

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint,
            num_established: 0,
            cause: None,
        });
        assert_eq!(
            event_loop.recent_sessions.back().unwrap().outcome,
            P2pSessionOutcome::TransportError
        );
        assert_eq!(event_loop.path_metrics[&P2pPath::Direct].sessions_closed, 1);
    }

    #[tokio::test]
    async fn transfer_history_does_not_retain_unknown_peers() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([75; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        let peer = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([76; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();

        event_loop.record_transfer(peer, Some(P2pPath::Direct), 10, 20);
        assert!(!event_loop.transfer_counters.contains_key(&peer));
        assert!(!event_loop.path_transfer_counters.contains_key(&peer));

        event_loop
            .persistent_addresses
            .insert(peer, BTreeSet::new());
        event_loop.record_transfer(peer, Some(P2pPath::Direct), 10, 20);
        assert_eq!(event_loop.transfer_counters[&peer].sent, 10);
        assert_eq!(
            event_loop.path_transfer_counters[&peer][&P2pPath::Direct].received,
            20
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
        event_loop.tor_mode = TorMode::PreferTor;
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

        event_loop.add_learned_address(peer, first.clone()).unwrap();
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&1));
        assert!(!event_loop.persistent_addresses.contains_key(&peer));
        assert_eq!(event_loop.learned_addresses[&peer].addresses.len(), 1);
        event_loop
            .replace_learned_addresses(peer, vec![first], unix_seconds() + 300)
            .unwrap();
        assert_eq!(event_loop.learned_addresses[&peer].addresses.len(), 1);
        event_loop.record_transfer(peer, Some(P2pPath::Direct), 10, 20);
        assert!(event_loop.transfer_counters.contains_key(&peer));
        assert!(event_loop.path_transfer_counters.contains_key(&peer));
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
        assert!(!event_loop.fallback_tiers.contains_key(&peer));
        assert!(!event_loop.transfer_counters.contains_key(&peer));
        assert!(!event_loop.path_transfer_counters.contains_key(&peer));

        for port in 4200..4200 + MAX_ENDPOINTS_PER_PEER {
            let address = format!("/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{peer}")
                .parse()
                .unwrap();
            event_loop.add_learned_address(peer, address).unwrap();
        }
        let excess = format!("/ip4/127.0.0.1/udp/4300/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        assert!(event_loop.add_learned_address(peer, excess).is_err());
        assert_eq!(
            event_loop.learned_addresses[&peer].addresses.len(),
            MAX_ENDPOINTS_PER_PEER
        );
    }

    #[tokio::test]
    async fn learned_endpoint_cache_rejects_unbounded_peer_churn() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([77; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        for index in 0..MAX_LEARNED_ENDPOINT_PEERS {
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let peer = mb_core::KeyMaterial::from_seed(&Seed::from_bytes(seed))
                .node_id()
                .libp2p_peer_id()
                .unwrap();
            event_loop.learned_addresses.insert(
                peer,
                LearnedAddresses {
                    addresses: BTreeSet::new(),
                    expires_at: tokio::time::Instant::now() + DHT_TTL,
                },
            );
        }
        let peer = mb_core::KeyMaterial::from_seed(&Seed::from_bytes([78; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let address = format!("/ip4/127.0.0.1/udp/4400/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        assert!(event_loop.add_learned_address(peer, address).is_err());
        assert_eq!(
            event_loop.learned_addresses.len(),
            MAX_LEARNED_ENDPOINT_PEERS
        );
    }

    #[tokio::test]
    async fn unknown_identify_peers_cannot_consume_authorized_endpoint_quota() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([66; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();

        for index in 0..=MAX_LEARNED_ENDPOINT_PEERS {
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let peer = KeyMaterial::from_seed(&Seed::from_bytes(seed))
                .node_id()
                .libp2p_peer_id()
                .unwrap();
            let address: Multiaddr =
                format!("/ip4/127.0.0.1/udp/{}/quic-v1", 10_000 + index % 50_000)
                    .parse()
                    .unwrap();
            event_loop.add_identified_address(peer, address).unwrap();
        }
        assert!(event_loop.learned_addresses.is_empty());
        assert_eq!(
            event_loop.opportunistic_addresses.len(),
            MAX_OPPORTUNISTIC_ENDPOINT_PEERS
        );

        let authorized = KeyMaterial::from_seed(&Seed::from_bytes([67; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        event_loop
            .persistent_addresses
            .insert(authorized, BTreeSet::new());
        let address: Multiaddr = "/ip4/127.0.0.1/udp/4400/quic-v1".parse().unwrap();
        event_loop
            .add_identified_address(authorized, address.clone())
            .unwrap();
        assert_eq!(
            event_loop.learned_addresses[&authorized].addresses,
            BTreeSet::from([address])
        );
        assert!(!event_loop.opportunistic_addresses.contains_key(&authorized));
    }

    #[tokio::test]
    async fn uncertified_recovery_addresses_are_attempt_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([69; 32])).unwrap();
        let local_id = node.keys().node_id();
        let (_client, mut event_loop) =
            build_p2p(Arc::new(Mutex::new(node)), config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::Auto;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([68; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let address = onion_listener_address(target).unwrap();
        let identified: Multiaddr = "/ip4/127.0.0.1/udp/4301/quic-v1".parse().unwrap();
        let scope = Uuid::new_v4();

        event_loop
            .add_recovery_addresses(scope, peer, vec![address], unix_seconds() + 300)
            .unwrap();
        event_loop
            .add_identified_address(peer, identified.clone())
            .unwrap();

        assert!(event_loop.recovery_addresses.contains_key(&scope));
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&2));
        assert!(!event_loop.learned_addresses.contains_key(&peer));
        assert!(event_loop.recovery_addresses[&scope].addresses[&peer].contains(&identified));
        event_loop.clear_recovery_addresses(scope);
        event_loop.add_identified_address(peer, identified).unwrap();
        assert!(!event_loop.recovery_addresses.contains_key(&scope));
        assert!(event_loop.recovery_quarantine.contains_key(&peer));
        assert!(!event_loop.learned_addresses.contains_key(&peer));
        assert!(!event_loop.opportunistic_addresses.contains_key(&peer));
        assert!(!event_loop.fallback_tiers.contains_key(&peer));
        assert!(!event_loop.retains_transfer_history(peer));
    }

    #[tokio::test]
    async fn fallback_tier_lives_until_the_closed_request_is_terminal() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([109; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::Auto;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([110; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let onion = onion_listener_address(target).unwrap();
        let scope = Uuid::new_v4();

        event_loop
            .add_recovery_addresses(scope, peer, vec![onion.clone()], unix_seconds() + 300)
            .unwrap();
        let connection = ConnectionId::new_unchecked(1101);
        event_loop
            .connection_paths
            .insert(connection, (peer, P2pPath::Tor));

        let call = tokio::spawn({
            let client = client.clone();
            async move { client.call(target, PeerRequest::Profile).await }
        });
        let command = event_loop.commands.recv().await.unwrap();
        event_loop.handle_command(command).unwrap();
        let request_id = *event_loop.pending_requests.keys().next().unwrap();

        event_loop.clear_recovery_addresses(scope);
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&2));
        assert!(event_loop.retained_peer_addresses(peer).is_empty());

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint: ConnectedPoint::Dialer {
                address: onion,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: 0,
            cause: None,
        });
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&2));
        assert!(event_loop.closed_connection_paths.contains_key(&connection));

        event_loop.handle_peer_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: connection,
            request_id,
            error: request_response::OutboundFailure::ConnectionClosed,
        });
        assert!(!event_loop.fallback_tiers.contains_key(&peer));
        assert!(event_loop.pending_requests.is_empty());
        assert!(event_loop.queued_requests.is_empty());
        assert!(call.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn fallback_tier_is_removed_when_its_last_endpoint_and_connection_are_gone() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([111; 32]);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let (_client, mut event_loop) = build_p2p(node, config(local_id)).unwrap();
        event_loop.tor_mode = TorMode::Auto;
        let target = KeyMaterial::from_seed(&Seed::from_bytes([112; 32])).node_id();
        let peer = target.libp2p_peer_id().unwrap();
        let onion = onion_listener_address(target).unwrap();
        let scope = Uuid::new_v4();

        event_loop
            .add_recovery_addresses(scope, peer, vec![onion.clone()], unix_seconds() + 300)
            .unwrap();
        let connection = ConnectionId::new_unchecked(1102);
        event_loop
            .connection_paths
            .insert(connection, (peer, P2pPath::Tor));

        event_loop.clear_recovery_addresses(scope);
        assert_eq!(event_loop.fallback_tiers.get(&peer), Some(&2));

        event_loop.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint: ConnectedPoint::Dialer {
                address: onion,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: 0,
            cause: None,
        });

        assert!(!event_loop.fallback_tiers.contains_key(&peer));
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
        assert!(
            select_endpoint_record(publisher, vec![make(4, 5), make(3, 3), make(3, 4)]).is_err()
        );
    }

    #[tokio::test]
    async fn uncertified_recovery_bundle_is_never_made_durable() {
        let temp = tempfile::tempdir().unwrap();
        let subject_seed = Seed::from_bytes([76; 32]);
        let subject = KeyMaterial::from_seed(&subject_seed).node_id();
        let publisher_keys = KeyMaterial::from_seed(&Seed::from_bytes([75; 32]));
        let publisher = publisher_keys.node_id();
        let provider = publisher.libp2p_peer_id().unwrap().to_string();
        let expires = unix_seconds() + 300;
        let make = |sequence, marker| {
            let value = mb_core::RecoveryBundle {
                format_version: 1,
                subject,
                publisher,
                sequence,
                expires_at_unix_seconds: expires,
                sealed: mb_core::SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [marker; 32],
                    nonce: [marker; 24],
                    ciphertext: vec![marker; 64],
                },
            };
            let signed =
                SignedRecord::sign(b"mutualbackup/recovery-bundle/v1", value, &publisher_keys)
                    .unwrap();
            DhtRecord {
                publisher: None,
                value: canonical_bytes(&signed).unwrap(),
            }
        };
        let node = Arc::new(Mutex::new(
            Node::open(temp.path(), subject_seed.clone()).unwrap(),
        ));
        let selected = select_recovery_bundle_candidate(
            node.clone(),
            &provider,
            subject,
            vec![make(1, 1), make(2, 2)],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(selected.selected.value.sequence, 2);
        assert_eq!(selected.observations.len(), 2);
        assert!(
            node.lock()
                .unwrap()
                .observed_recovery_records(subject)
                .unwrap()
                .is_empty()
        );
        drop(node);

        let reopened = Arc::new(Mutex::new(Node::open(temp.path(), subject_seed).unwrap()));
        assert!(
            select_recovery_bundle_candidate(reopened.clone(), &provider, subject, Vec::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            select_recovery_bundle_candidate(
                reopened,
                &provider,
                subject,
                vec![make(3, 3), make(3, 9)],
            )
            .await
            .is_err()
        );
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
        let direct = connection
            .path_transfers
            .iter()
            .find(|transfer| transfer.path == P2pPath::Direct)
            .unwrap();
        assert!(direct.application_bytes_sent > 0);
        assert!(direct.application_bytes_received > 0);

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
    async fn live_request_timeout_quarantines_only_its_connection_and_retries_a_duplicate() {
        let temp = tempfile::tempdir().unwrap();
        let target_seed = Seed::from_bytes([86; 32]);
        let target_id = KeyMaterial::from_seed(&target_seed).node_id();
        let target_peer = target_id.libp2p_peer_id().unwrap();
        let client_seed = (87_u8..=u8::MAX)
            .map(|byte| Seed::from_bytes([byte; 32]))
            .find(|seed| {
                KeyMaterial::from_seed(seed)
                    .node_id()
                    .libp2p_peer_id()
                    .unwrap()
                    > target_peer
            })
            .expect("test seeds include a client ordered after the target");
        let client_node = Node::open(temp.path().join("client"), client_seed).unwrap();
        let client_id = client_node.keys().node_id();
        let good_node = Node::open(temp.path().join("good"), target_seed.clone()).unwrap();
        let blackhole_node = Node::open(temp.path().join("blackhole"), target_seed).unwrap();

        let (client, mut client_loop) =
            build_p2p(Arc::new(Mutex::new(client_node)), config(client_id)).unwrap();
        let (good, good_loop) =
            build_p2p(Arc::new(Mutex::new(good_node)), config(target_id)).unwrap();
        let (blackhole, mut blackhole_loop) =
            build_p2p(Arc::new(Mutex::new(blackhole_node)), config(target_id)).unwrap();
        let good_task = tokio::spawn(good_loop.run());
        let blackhole_task = tokio::spawn(async move {
            let mut held_channels = Vec::new();
            loop {
                tokio::select! {
                    Some(command) = blackhole_loop.commands.recv() => {
                        if blackhole_loop.handle_command(command)? {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                    event = blackhole_loop.swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::Peer(
                                request_response::Event::Message {
                                    message: request_response::Message::Request { channel, .. },
                                    ..
                                },
                            )) => held_channels.push(channel),
                            event => blackhole_loop.handle_swarm_event(event),
                        }
                    }
                }
            }
        });

        let good_address = listening_address(&good).await;
        let blackhole_address = listening_address(&blackhole).await;
        for address in [&good_address, &blackhole_address] {
            client_loop
                .add_learned_address(
                    target_peer,
                    address
                        .clone()
                        .with(libp2p::multiaddr::Protocol::P2p(target_peer)),
                )
                .unwrap();
        }
        for address in [good_address, blackhole_address] {
            client_loop
                .swarm
                .dial(
                    SwarmDialOpts::peer_id(target_peer)
                        .addresses(vec![address])
                        .condition(PeerCondition::Always)
                        .build(),
                )
                .unwrap();
        }
        let client_task = tokio::spawn(client_loop.run());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let active = client
                    .status()
                    .await
                    .unwrap()
                    .active_sessions
                    .into_iter()
                    .filter(|session| session.peer_id == target_peer.to_string())
                    .count();
                if active >= 2 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("client did not establish both same-identity QUIC sessions");

        let calls = (0..4)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move { client.profile(target_id).await })
            })
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(35), async {
            for call in calls {
                assert_eq!(call.await.unwrap().unwrap().member.node_id, target_id);
            }
        })
        .await
        .expect("timed-out duplicate requests did not retry on the healthy session");
        let status = client.status().await.unwrap();
        let direct = status
            .path_metrics
            .iter()
            .find(|metrics| metrics.path == P2pPath::Direct)
            .unwrap();
        assert!(direct.requests_failed >= 1, "no live request timed out");
        assert!(direct.requests_succeeded >= 4);
        assert!(status.recent_sessions.iter().any(|session| {
            session.peer_id == target_peer.to_string()
                && session.outcome == P2pSessionOutcome::TransportError
        }));

        client.shutdown().await.unwrap();
        good.shutdown().await.unwrap();
        client_task.await.unwrap().unwrap();
        good_task.await.unwrap().unwrap();
        blackhole_task.abort();
        assert!(blackhole_task.await.unwrap_err().is_cancelled());
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
        let fallback_source_node = guild_nodes.next().unwrap();
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
        let dcutr_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let status = first_client.status().await.unwrap();
            let saw_hole_punch = status.peers.iter().any(|peer| {
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
            assert!(
                tokio::time::Instant::now() < dcutr_deadline,
                "DCUtR did not replace the relay circuit with a direct QUIC path:\n{status:#?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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
                && peer.path_transfers.iter().any(|transfer| {
                    transfer.path == P2pPath::HolePunched
                        && transfer.application_bytes_sent > 0
                        && transfer.application_bytes_received > 0
                })
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
        let fallback_source_id = fallback_source_node.keys().node_id();
        let mut fallback_source_config = config(fallback_source_id);
        fallback_source_config.listen_addresses.clear();
        fallback_source_config.enable_relay_server = false;
        fallback_source_config.enable_hole_punching = false;
        fallback_source_config.relay_reservation_addresses = vec![relay_address.clone()];
        let (fallback_source_client, fallback_source_loop) = build_p2p(
            Arc::new(Mutex::new(fallback_source_node)),
            fallback_source_config,
        )
        .unwrap();
        let fallback_source_task = tokio::spawn(fallback_source_loop.run());
        let unreachable_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable_direct: Multiaddr = format!(
            "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
            unreachable_socket.local_addr().unwrap().port(),
            fallback_client.local_peer_id()
        )
        .parse()
        .unwrap();
        drop(unreachable_socket);
        fallback_source_client
            .add_peer_address(fallback_id, unreachable_direct)
            .await
            .unwrap();
        fallback_source_client
            .add_peer_address(fallback_id, relayed_address(&fallback_client).await)
            .await
            .unwrap();
        // The request which discovers that the preferred direct path is dead
        // must continue over the next policy tier without a caller retry.
        let profile = fallback_source_client.profile(fallback_id).await.unwrap();
        assert_eq!(profile.member.node_id, fallback_id);
        let status = fallback_source_client.status().await.unwrap();
        assert!(
            status.peers.iter().any(|peer| {
                peer.peer_id == fallback_client.local_peer_id()
                    && peer.application_bytes_sent > 0
                    && peer.application_bytes_received > 0
                    && peer.path_transfers.iter().any(|transfer| {
                        transfer.path == P2pPath::RelayFallback
                            && transfer.application_bytes_sent > 0
                            && transfer.application_bytes_received > 0
                    })
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
        fallback_source_client.shutdown().await.unwrap();
        nonmember_client.shutdown().await.unwrap();
        relay_client.shutdown().await.unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
        fallback_task.await.unwrap().unwrap();
        fallback_source_task.await.unwrap().unwrap();
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
    async fn relay_membership_updates_when_dht_maintenance_is_disabled() {
        let temp = tempfile::tempdir().unwrap();
        let seeds = (86_u8..=90)
            .map(|value| Seed::from_bytes([value; 32]))
            .collect::<Vec<_>>();
        let mut nodes = Vec::new();
        let mut clients = Vec::new();
        let mut relay_members = Vec::new();
        let mut tasks = Vec::new();
        for (index, seed) in seeds.into_iter().enumerate() {
            let node = Node::open(temp.path().join(format!("node-{index}")), seed).unwrap();
            let node_id = node.keys().node_id();
            let node = Arc::new(Mutex::new(node));
            let mut node_config = config(node_id);
            node_config.enable_dht_maintenance = false;
            let (client, event_loop) = build_p2p(node.clone(), node_config).unwrap();
            relay_members.push(event_loop.relay_members.clone());
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
        form_test_guild(&nodes, &clients, &addresses, &endpoints).await;

        for (node, client) in nodes.iter().zip(&clients) {
            sync_relay_membership_once(node.clone(), client)
                .await
                .unwrap();
        }
        assert!(
            relay_members
                .iter()
                .all(|members| members.read().is_ok_and(|members| members.len() == 5))
        );

        for client in &clients {
            client.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
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
        let owner_content = |owner_index: usize| {
            let len = if owner_index == 1 {
                V1_SECTOR_SIZE * 10 + 123
            } else {
                90_000
            };
            (0..len)
                .map(|offset| ((offset + owner_index * 29) % 251) as u8)
                .collect::<Vec<_>>()
        };

        let mut watcher_task = None;
        for (owner_index, expected_generation) in [(1_usize, 1_u64), (2, 2)] {
            let source = run_root.join(format!("source-{owner_index}"));
            std::fs::create_dir_all(source.join("documents")).unwrap();
            std::fs::write(
                source.join("documents/content.bin"),
                owner_content(owner_index),
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
            owner_content(2)
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
        install_legacy_recovery_observation_poison(&recovered_state, &seeds[1], &seeds[4]);
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
        // This covers DHT discovery, certified-state validation, endpoint
        // refresh, all coding groups, and publication. Keep the integration
        // bound above the protocol's single 20-second request timeout; focused
        // tests separately prove that abandoned requests release their state.
        let recovered = tokio::time::timeout(
            Duration::from_secs(60),
            recover_from_dht(recovered_node.clone(), &recovery_client, &restored),
        )
        .await
        .expect("large recovery with three live holders must not wait for abandoned requests")
        .unwrap();
        assert_eq!(recovered.generation, 2);
        assert_eq!(
            std::fs::read(restored.join("documents/content.bin")).unwrap(),
            owner_content(1)
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
        let publishing_restore = run_root.join("publishing-restore-node-2");
        crate::snapshot::interrupt_next_restore_after_rename();
        assert!(
            nodes[2]
                .lock()
                .unwrap()
                .restore_snapshot(None, &publishing_restore)
                .is_err()
        );
        assert!(publishing_restore.is_dir());
        nodes[2]
            .lock()
            .unwrap()
            .forget_local_sector(&forgotten_sector)
            .unwrap();
        for index in [0_usize, 2, 3] {
            clients[index].shutdown().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let local_resume = tokio::time::timeout(
            Duration::from_secs(1),
            recover_from_dht(recovered_node.clone(), &recovery_client, &restored),
        )
        .await
        .expect("installed recovery must not wait for a DHT quorum")
        .unwrap();
        assert_eq!(local_resume, recovered);
        recovery_client.shutdown().await.unwrap();
        recovery_task.await.unwrap().unwrap();
        drop(recovered_node);
        let mut reopened_recovery = Node::open(&recovered_state, seeds[1].clone()).unwrap();
        let retained = reopened_recovery
            .observed_recovery_records(recovered_id)
            .unwrap();
        let allowed_provider_hashes = final_checkpoint
            .checkpoint
            .members
            .iter()
            .map(|member| {
                let peer_id = member.node_id.libp2p_peer_id().unwrap().to_string();
                *blake3::hash(peer_id.as_bytes()).as_bytes()
            })
            .collect::<BTreeSet<_>>();
        assert!(retained.len() >= 3);
        assert!(retained.len() <= 4);
        assert!(retained.iter().all(|(_, bytes)| {
            decode_canonical::<SignedRecord<mb_core::RecoveryBundle>>(bytes)
                .unwrap()
                .value
                .sequence
                != LEGACY_MEMBER_POISON_SEQUENCE
        }));
        assert!(
            retained
                .iter()
                .all(|(provider_hash, _)| allowed_provider_hashes.contains(provider_hash))
        );
        drop(reopened_recovery);

        for client in &clients {
            let _ = client.shutdown().await;
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        tokio::time::timeout(
            Duration::from_secs(1),
            restore_snapshot_with_p2p(nodes[2].clone(), &clients[2], None, &publishing_restore),
        )
        .await
        .expect("publishing restore retry must not contact unavailable peers")
        .unwrap();
        assert!(nodes[2].lock().unwrap().restore_job_count().unwrap() == 0);
        drop(clients);
        drop(nodes);
        std::fs::remove_dir_all(run_root).unwrap();
    }
}
