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

use mb_core::{Member, NodeId, SignedRecord, canonical_bytes};

use super::{
    Node, NodeServerConfig, NodeService, PEER_RESPONSE_DOMAIN, PeerRequest, PeerRequestEnvelope,
    PeerResponse, PeerResponseEnvelope, make_peer_request, process_peer_request,
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
                let mut connected_peers = self
                    .swarm
                    .connected_peers()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                connected_peers.sort();
                let _ = response.send(P2pStatus {
                    peer_id: self.swarm.local_peer_id().to_string(),
                    listen_addresses,
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
}
