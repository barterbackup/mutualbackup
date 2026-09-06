use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, StreamProtocol, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, dcutr, identify, kad, noise, ping, relay,
    request_response, yamux,
};
use tokio::sync::{mpsc, oneshot};

use mb_core::{
    CodingGroup, GuildCheckpoint, GuildGenesis, GuildInvite, InformationRole, Member,
    MemberSignature, NodeId, ParityRole, QuorumCheckpoint, QuorumGuildGenesis, SectorId, SectorRef,
    ShardRole, SignedRecord, StorageAcknowledgement, UserRevision, V1_CATALOG_PAGE_BYTES,
    V1_MAX_CATALOG_BYTES, V1_MAX_CODING_GROUPS, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS,
    V1_SECTOR_SIZE, canonical_bytes, decode_canonical, encode_3_2, sector_root,
};
use mb_store::ParityObject;
use uuid::Uuid;

use super::{
    BackupDescriptor, BackupJob, CheckpointObjectKind, GuildPeer, Node, NodeServerConfig,
    NodeService, PEER_RESPONSE_DOMAIN, PeerRequest, PeerRequestEnvelope, PeerResponse,
    PeerResponseEnvelope, checked_catalog_page_count, make_peer_request, process_peer_request,
    storage_operation_id,
};

const P2P_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/peer/1");
const IDENTIFY_PROTOCOL: &str = "/mutualbackup/identify/1";
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/mutualbackup/kad/1");
const COMMAND_CAPACITY: usize = 128;
const DHT_TTL: Duration = Duration::from_secs(15 * 60);
const DHT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DHT_MAX_PACKET_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub external_addresses: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub relay_reservation_addresses: Vec<Multiaddr>,
    pub enable_relay_server: bool,
    pub public_endpoint: String,
    pub failure_domain: String,
    pub trusted_coordinator: NodeId,
    pub max_connections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pPeerProfile {
    pub member: Member,
    pub endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pStatus {
    pub peer_id: String,
    pub listen_addresses: Vec<String>,
    pub advertised_addresses: Vec<String>,
    pub connected_peers: Vec<String>,
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
}

pub struct P2pEventLoop {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    inbound_results: mpsc::Receiver<InboundResult>,
    inbound_sender: mpsc::Sender<InboundResult>,
    pending_requests: HashMap<request_response::OutboundRequestId, PendingRequest>,
    pending_dht: HashMap<kad::QueryId, PendingDht>,
    service: Arc<NodeService>,
    server_config: NodeServerConfig,
    advertised_addresses: Vec<Multiaddr>,
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
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
}

enum Command {
    AddAddress {
        peer: PeerId,
        address: Multiaddr,
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
    response: oneshot::Sender<Result<PeerResponse>>,
}

struct InboundResult {
    channel: request_response::ResponseChannel<SignedRecord<PeerResponseEnvelope>>,
    response: Result<SignedRecord<PeerResponseEnvelope>>,
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

pub fn build_p2p(node: Arc<Mutex<Node>>, config: P2pConfig) -> Result<(P2pClient, P2pEventLoop)> {
    if config.listen_addresses.is_empty()
        || config.failure_domain.is_empty()
        || config.max_connections == 0
    {
        bail!("invalid libp2p configuration");
    }
    let (identity, reader_config) = {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        node.configure_failure_domain(&config.failure_domain)?;
        (node.keys().libp2p_keypair(), node.reader_config())
    };
    let local_peer_id = identity.public().to_peer_id();
    let relay_server_enabled = config.enable_relay_server;
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
                peer: request_response::cbor::Behaviour::new(
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
                    relay_server_enabled
                        .then(|| relay::Behaviour::new(peer_id, relay::Config::default())),
                ),
                dcutr: dcutr::Behaviour::new(peer_id),
                autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                ping: ping::Behaviour::new(ping::Config::new()),
            }
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    for address in &config.listen_addresses {
        swarm
            .listen_on(address.clone())
            .with_context(|| format!("cannot listen on {address}"))?;
    }
    for address in &config.external_addresses {
        swarm.add_external_address(address.clone());
    }
    for address in config
        .bootstrap_addresses
        .iter()
        .chain(&config.relay_reservation_addresses)
    {
        add_address_to_swarm(&mut swarm, address.clone())?;
        if let Err(error) = swarm.dial(address.clone()) {
            tracing::warn!(%address, %error, "initial libp2p dial was rejected");
        }
    }
    for address in &config.relay_reservation_addresses {
        let reservation = address
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        swarm
            .listen_on(reservation.clone())
            .with_context(|| format!("cannot request relay reservation through {reservation}"))?;
    }
    if !config.bootstrap_addresses.is_empty()
        && let Err(error) = swarm.behaviour_mut().kademlia.bootstrap()
    {
        tracing::warn!(%error, "initial Kademlia bootstrap could not start");
    }

    let service = Arc::new(NodeService {
        writer: node,
        reader_config,
        readers: Mutex::new(Vec::new()),
        max_readers: config.max_connections,
    });
    let server_config = NodeServerConfig {
        listen: "127.0.0.1:1".parse().expect("constant socket address"),
        public_endpoint: config.public_endpoint,
        failure_domain: config.failure_domain,
        trusted_coordinator: config.trusted_coordinator,
        max_connections: config.max_connections,
    };
    let (command_sender, command_receiver) = mpsc::channel(COMMAND_CAPACITY);
    let (inbound_sender, inbound_results) = mpsc::channel(COMMAND_CAPACITY);
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
            pending_requests: HashMap::new(),
            pending_dht: HashMap::new(),
            service,
            server_config,
            advertised_addresses: config.external_addresses,
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
        acknowledgement.verify(b"mutualbackup/storage-acknowledgement/v1")?;
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
    pub async fn run(mut self) -> Result<()> {
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
                            if self.swarm.behaviour_mut().peer.send_response(result.channel, response).is_err() {
                                tracing::warn!("peer disconnected before its response was ready");
                            }
                        }
                        Err(error) => tracing::warn!(%error, "peer request worker failed"),
                    }
                }
                event = self.swarm.select_next_some() => self.handle_swarm_event(event),
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
                let result = add_known_address(&mut self.swarm, peer, address);
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
                    self.advertised_addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                };
                advertised_addresses.sort();
                let mut connected_peers = self
                    .swarm
                    .connected_peers()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                connected_peers.sort();
                let _ = response.send(P2pStatus {
                    peer_id: self.swarm.local_peer_id().to_string(),
                    listen_addresses,
                    advertised_addresses,
                    connected_peers,
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
                tracing::info!(?event, "DCUtR event");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                tracing::debug!(?event, "AutoNAT event");
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "libp2p listening");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => tracing::info!(peer = %peer_id, ?endpoint, "libp2p connection established"),
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
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    if request.signer.libp2p_peer_id().ok() != Some(peer) {
                        tracing::warn!(%peer, "application signer does not match libp2p peer");
                        return;
                    }
                    let service = self.service.clone();
                    let config = self.server_config.clone();
                    let sender = self.inbound_sender.clone();
                    tokio::task::spawn_blocking(move || {
                        let response = process_peer_request(service, &config, request);
                        let _ = sender.blocking_send(InboundResult { channel, response });
                    });
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(pending) = self.pending_requests.remove(&request_id) {
                        let result = if pending.peer == peer {
                            validate_outbound_response(response, &pending)
                        } else {
                            Err(anyhow::anyhow!("libp2p response came from the wrong peer"))
                        };
                        let _ = pending.response.send(result);
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(pending) = self.pending_requests.remove(&request_id) {
                    let _ = pending
                        .response
                        .send(Err(anyhow::anyhow!("libp2p request failed: {error}")));
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::warn!(%peer, %error, "libp2p inbound request failed");
            }
            request_response::Event::ResponseSent { .. } => {}
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
                    records.push(DhtRecord {
                        publisher: found.record.publisher.map(|peer| peer.to_string()),
                        value: found.record.value,
                    });
                    if last {
                        let _ = response.send(Ok(records));
                    } else {
                        self.pending_dht
                            .insert(id, PendingDht::Get { records, response });
                    }
                }
                Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
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
                    providers.extend(found.into_iter().map(|peer| peer.to_string()));
                    if last {
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
                tracing::warn!(
                    revision = %job.descriptor.revision_id,
                    %error,
                    "coordinator backup attempt deferred"
                );
                let descriptor = job.descriptor.clone();
                let message = format!("{error:#}");
                node_blocking(node.clone(), move |node| {
                    node.defer_backup_job(&descriptor, &message)
                })
                .await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
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
    acknowledgement.verify(b"mutualbackup/storage-acknowledgement/v1")?;
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
        || response.value.format_version != 1
        || response.value.request_id != pending.request_id
        || response.value.recipient != pending.response_recipient
        || response.value.request_hash != pending.request_hash
    {
        bail!("libp2p peer response context mismatch");
    }
    response.value.result.map_err(anyhow::Error::msg)
}

fn add_address_to_swarm(swarm: &mut Swarm<Behaviour>, address: Multiaddr) -> Result<()> {
    let peer = address
        .iter()
        .find_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .context("peer multiaddress has no /p2p identity")?;
    add_known_address(swarm, peer, address)
}

fn add_known_address(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    mut address: Multiaddr,
) -> Result<()> {
    if address.iter().last() == Some(libp2p::multiaddr::Protocol::P2p(peer)) {
        address.pop();
    }
    if address.is_empty() {
        bail!("peer address has no transport components");
    }
    swarm.add_peer_address(peer, address.clone());
    swarm.behaviour_mut().kademlia.add_address(&peer, address);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::Seed;

    fn config(node_id: NodeId) -> P2pConfig {
        P2pConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            external_addresses: Vec::new(),
            bootstrap_addresses: Vec::new(),
            relay_reservation_addresses: Vec::new(),
            enable_relay_server: true,
            public_endpoint: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            failure_domain: node_id.to_string(),
            trusted_coordinator: node_id,
            max_connections: 8,
        }
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

    fn peer_endpoint(client: &P2pClient, address: Multiaddr) -> String {
        address
            .with(libp2p::multiaddr::Protocol::P2p(client.local_peer_id))
            .to_string()
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
        for (index, seed) in seeds.into_iter().enumerate() {
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
        for (index, seed) in seeds.into_iter().enumerate() {
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

        for client in &clients {
            client.shutdown().await.unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        drop(clients);
        drop(nodes);
        std::fs::remove_dir_all(run_root).unwrap();
    }
}
