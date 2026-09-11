use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arti_client::config::{CfgPath, TorClientConfig};
use arti_client::{DataStream, TorClient};
use data_encoding::BASE32_NOPAD;
use fs2::FileExt;
use futures::future::{BoxFuture, Ready, ready};
use futures::{Stream, StreamExt};
use libp2p::Multiaddr;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use mb_core::NodeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc, watch};
use tor_config::sources::MustRead;
use tor_config::{ConfigurationSource, ConfigurationSources, ExplicitOrAuto};
use tor_config_path::arti_client_base_resolver;
use tor_hscrypto::pk::{HsId, HsIdKeypair};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use tor_rtcompat::PreferredRuntime;
use zeroize::Zeroizing;

const ONION_SERVICE_NICKNAME: &str = "mutualbackup";
pub const ONION_SERVICE_PORT: u16 = 443;
const BOOTSTRAP_RETRY: Duration = Duration::from_secs(15);
const SERVICE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_SHUTDOWN_POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TorMode {
    #[default]
    Auto,
    PreferTor,
    RequireTor,
    DisableTor,
}

impl TorMode {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::DisableTor)
    }

    pub fn requires_tor(self) -> bool {
        matches!(self, Self::RequireTor)
    }
}

impl std::fmt::Display for TorMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::PreferTor => "prefer-tor",
            Self::RequireTor => "require-tor",
            Self::DisableTor => "disable-tor",
        })
    }
}

impl FromStr for TorMode {
    type Err = TorModeParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "prefer-tor" => Ok(Self::PreferTor),
            "require-tor" => Ok(Self::RequireTor),
            "disable-tor" => Ok(Self::DisableTor),
            _ => Err(TorModeParseError(value.to_owned())),
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid Tor mode {0:?}; expected auto, prefer-tor, require-tor, or disable-tor")]
pub struct TorModeParseError(String);

#[derive(Clone, Debug)]
pub struct TorTransportConfig {
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub arti_config_file: Option<PathBuf>,
    pub max_inbound_streams: usize,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct TorTransportError {
    message: String,
}

impl TorTransportError {
    fn new(error: impl std::fmt::Display) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

enum InboundEvent {
    Stream(Box<DataStream>),
    Error(String),
}

/// Raw ordered-stream transport for libp2p Noise+yamux over Arti.
pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
    listen_address: Multiaddr,
    listeners: HashMap<ListenerId, Multiaddr>,
    pending_events: VecDeque<
        TransportEvent<
            Ready<std::result::Result<DataStream, TorTransportError>>,
            TorTransportError,
        >,
    >,
    incoming: mpsc::Receiver<InboundEvent>,
    service_status: tor_hsservice::status::OnionServiceStatusStream,
    reachable: bool,
    shutdown: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
    bootstrap_task: tokio::task::JoinHandle<()>,
    _service: Arc<RunningOnionService>,
    _state_lock: File,
}

impl TorTransport {
    pub async fn new(
        config: TorTransportConfig,
        identity_seed: Zeroizing<[u8; 32]>,
        node_id: NodeId,
    ) -> Result<Self> {
        if config.max_inbound_streams == 0 {
            bail!("Tor inbound stream limit must be greater than zero");
        }
        let loaded = load_arti_config(&config)?;
        prepare_private_directory(&loaded.state_dir, "Tor state")?;
        prepare_private_directory(&loaded.cache_dir, "Tor cache")?;
        let canonical_state = fs::canonicalize(&loaded.state_dir).context("resolve Tor state")?;
        let canonical_cache = fs::canonicalize(&loaded.cache_dir).context("resolve Tor cache")?;
        if canonical_state == canonical_cache
            || canonical_state.starts_with(&canonical_cache)
            || canonical_cache.starts_with(&canonical_state)
        {
            bail!("Tor state and cache directories must not overlap");
        }
        let state_lock = lock_tor_state(&loaded.state_dir)?;
        validate_onion_service_state(&loaded.state_dir)?;

        let client = TorClient::<PreferredRuntime>::builder()
            .config(loaded.config)
            .create_unbootstrapped_async()
            .await
            .context("create Arti client")?;
        let nickname: HsNickname = ONION_SERVICE_NICKNAME
            .to_owned()
            .try_into()
            .map_err(|error| anyhow::anyhow!("invalid onion service nickname: {error}"))?;
        let service_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .context("build onion service configuration")?;

        let compact = Keypair::from_bytes(&identity_seed);
        let expanded = ExpandedKeypair::from(&compact);
        if expanded.public().as_bytes() != &node_id.0 {
            bail!("Tor identity does not match the MutualBackup Node ID");
        }
        let hsid = HsIdKeypair::from(expanded);
        drop(identity_seed);
        let Some((service, rend_requests)) = client
            .launch_onion_service_with_hsid(service_config, hsid)
            .context("launch Arti onion service")?
        else {
            bail!("Arti disabled the configured MutualBackup onion service");
        };

        let listen_address = onion_listener_address(node_id)?;
        let service_status = service.status_events();
        let (incoming_sender, incoming) = mpsc::channel(config.max_inbound_streams);
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let accept_task = spawn_accept_task(
            rend_requests,
            incoming_sender,
            shutdown_receiver,
            config.max_inbound_streams,
        );
        let bootstrap_client = Arc::clone(&client);
        let mut bootstrap_shutdown = shutdown.subscribe();
        let bootstrap_task = tokio::spawn(async move {
            loop {
                let attempt = tokio::select! {
                    _ = bootstrap_shutdown.changed() => return,
                    attempt = bootstrap_client.bootstrap() => attempt,
                };
                match attempt {
                    Ok(()) => {
                        tracing::info!("Arti client bootstrapped");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Arti bootstrap failed; retrying");
                        tokio::select! {
                            _ = bootstrap_shutdown.changed() => return,
                            _ = tokio::time::sleep(BOOTSTRAP_RETRY) => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            client,
            listen_address,
            listeners: HashMap::new(),
            pending_events: VecDeque::new(),
            incoming,
            service_status,
            reachable: service.status().state().is_fully_reachable(),
            shutdown,
            accept_task,
            bootstrap_task,
            _service: service,
            _state_lock: state_lock,
        })
    }

    pub fn listen_address(&self) -> &Multiaddr {
        &self.listen_address
    }

    fn change_reachability(&mut self, reachable: bool) {
        if self.reachable == reachable {
            return;
        }
        self.reachable = reachable;
        for (listener_id, listen_addr) in &self.listeners {
            self.pending_events.push_back(if reachable {
                TransportEvent::NewAddress {
                    listener_id: *listener_id,
                    listen_addr: listen_addr.clone(),
                }
            } else {
                TransportEvent::AddressExpired {
                    listener_id: *listener_id,
                    listen_addr: listen_addr.clone(),
                }
            });
        }
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.accept_task.abort();
        self.bootstrap_task.abort();
    }
}

/// Wait for Arti's background onion-service tasks to release their persistent
/// instance lock after the transport has been dropped.
///
/// `RunningOnionService` initiates shutdown on drop, but the state lock is held
/// by background tasks until they observe that signal. A daemon that returns to
/// its locked control loop must wait for this handoff before another unlock can
/// launch the same deterministic service nickname.
pub async fn wait_for_onion_service_shutdown(state_dir: &Path) -> Result<()> {
    let lock_path = state_dir
        .join("hss")
        .join(format!("{ONION_SERVICE_NICKNAME}.lock"));
    let deadline = tokio::time::Instant::now() + SERVICE_SHUTDOWN_TIMEOUT;
    loop {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = match options.open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open Arti service lock {}", lock_path.display()));
            }
        };
        if !file.metadata()?.is_file() {
            bail!("Arti service lock must be a regular file");
        }
        match file.try_lock_exclusive() {
            Ok(()) => {
                FileExt::unlock(&file).context("release Arti service shutdown probe")?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("probe Arti service shutdown"),
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for Arti onion service shutdown at {}",
                lock_path.display()
            );
        }
        tokio::time::sleep(SERVICE_SHUTDOWN_POLL).await;
    }
}

impl Transport for TorTransport {
    type Output = DataStream;
    type Error = TorTransportError;
    type ListenerUpgrade = Ready<std::result::Result<DataStream, TorTransportError>>;
    type Dial = BoxFuture<'static, std::result::Result<DataStream, TorTransportError>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> std::result::Result<(), TransportError<Self::Error>> {
        if addr != self.listen_address {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        self.listeners.insert(id, addr.clone());
        if self.reachable {
            self.pending_events.push_back(TransportEvent::NewAddress {
                listener_id: id,
                listen_addr: addr,
            });
        }
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        let Some(address) = self.listeners.remove(&id) else {
            return false;
        };
        if self.reachable {
            self.pending_events
                .push_back(TransportEvent::AddressExpired {
                    listener_id: id,
                    listen_addr: address,
                });
        }
        true
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> std::result::Result<Self::Dial, TransportError<Self::Error>> {
        let (hostname, port) = parse_onion_target(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        let client = Arc::clone(&self.client);
        Ok(Box::pin(async move {
            client
                .connect((hostname, port))
                .await
                .map_err(TorTransportError::new)
        }))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }
        loop {
            match Pin::new(&mut self.service_status).poll_next(cx) {
                Poll::Ready(Some(status)) => {
                    let reachable = status.state().is_fully_reachable();
                    tracing::debug!(state = ?status.state(), "Arti onion service status changed");
                    self.change_reachability(reachable);
                    if let Some(event) = self.pending_events.pop_front() {
                        return Poll::Ready(event);
                    }
                }
                Poll::Ready(None) => {
                    self.change_reachability(false);
                    if let Some(event) = self.pending_events.pop_front() {
                        return Poll::Ready(event);
                    }
                    break;
                }
                Poll::Pending => break,
            }
        }
        // Do not consume an accepted stream until libp2p has installed the
        // matching listener.  Arti can publish the service before Swarm polls
        // `listen_on`, and consuming here would otherwise drop that first
        // connection without ever yielding it to libp2p.
        if self.listeners.is_empty() {
            return Poll::Pending;
        }
        match self.incoming.poll_recv(cx) {
            Poll::Ready(Some(InboundEvent::Stream(stream))) => {
                let Some((listener_id, local_addr)) = self
                    .listeners
                    .iter()
                    .next()
                    .map(|(id, address)| (*id, address.clone()))
                else {
                    return Poll::Pending;
                };
                Poll::Ready(TransportEvent::Incoming {
                    listener_id,
                    upgrade: ready(Ok(*stream)),
                    local_addr: local_addr.clone(),
                    // Tor intentionally hides the client's network address and
                    // does not prove that it owns an onion service of its own.
                    // Reporting our listener here makes Identify tell the
                    // client that our onion address is its observed address,
                    // which in turn feeds a bogus AutoNAT probe.  An empty
                    // multiaddress is the explicit "unknown remote address"
                    // representation used by this transport.
                    send_back_addr: anonymous_inbound_address(),
                })
            }
            Poll::Ready(Some(InboundEvent::Error(message))) => {
                let Some(listener_id) = self.listeners.keys().next().copied() else {
                    return Poll::Pending;
                };
                Poll::Ready(TransportEvent::ListenerError {
                    listener_id,
                    error: TorTransportError { message },
                })
            }
            Poll::Ready(None) => {
                let Some((listener_id, listen_addr)) = self
                    .listeners
                    .iter()
                    .next()
                    .map(|(id, address)| (*id, address.clone()))
                else {
                    return Poll::Pending;
                };
                self.listeners.remove(&listener_id);
                let closed = TransportEvent::ListenerClosed {
                    listener_id,
                    reason: Err(TorTransportError {
                        message: "Arti onion stream acceptor stopped".to_owned(),
                    }),
                };
                if self.reachable {
                    self.pending_events.push_back(closed);
                    Poll::Ready(TransportEvent::AddressExpired {
                        listener_id,
                        listen_addr,
                    })
                } else {
                    Poll::Ready(closed)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn spawn_accept_task(
    rend_requests: impl Stream<Item = tor_hsservice::RendRequest> + Send + 'static,
    incoming: mpsc::Sender<InboundEvent>,
    mut shutdown: watch::Receiver<bool>,
    max_inbound_streams: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(max_inbound_streams));
        let mut requests = Box::pin(rend_requests);
        let mut rendezvous = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                Some(_) = rendezvous.join_next(), if !rendezvous.is_empty() => {}
                request = requests.next() => {
                    let Some(request) = request else { break };
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        tracing::warn!("rejected Tor rendezvous above the configured bound");
                        continue;
                    };
                    let sender = incoming.clone();
                    let mut task_shutdown = shutdown.clone();
                    rendezvous.spawn(async move {
                        let accepted = request.accept().await;
                        let mut stream_requests = match accepted {
                            Ok(requests) => Box::pin(requests),
                            Err(error) => {
                                let _ = sender.try_send(InboundEvent::Error(error.to_string()));
                                return;
                            }
                        };
                        loop {
                            let request = tokio::select! {
                                _ = task_shutdown.changed() => return,
                                request = stream_requests.next() => request,
                            };
                            let Some(request) = request else { break };
                            let allowed = matches!(
                                request.request(),
                                tor_proto::stream::IncomingStreamRequest::Begin(begin)
                                    if begin.port() == ONION_SERVICE_PORT
                            );
                            if !allowed {
                                tracing::warn!("rejected an onion stream for an unsupported port or command");
                                continue;
                            }
                            let slot = tokio::select! {
                                _ = task_shutdown.changed() => return,
                                slot = sender.reserve() => match slot {
                                    Ok(slot) => slot,
                                    Err(_) => return,
                                }
                            };
                            match request
                                .accept(tor_cell::relaycell::msg::Connected::new_empty())
                                .await
                            {
                                Ok(stream) => slot.send(InboundEvent::Stream(Box::new(stream))),
                                Err(error) => {
                                    slot.send(InboundEvent::Error(error.to_string()));
                                }
                            }
                        }
                        drop(permit);
                    });
                }
            }
        }
        rendezvous.abort_all();
        while rendezvous.join_next().await.is_some() {}
    })
}

struct LoadedArtiConfig {
    config: TorClientConfig,
    state_dir: PathBuf,
    cache_dir: PathBuf,
}

fn load_arti_config(config: &TorTransportConfig) -> Result<LoadedArtiConfig> {
    let Some(path) = &config.arti_config_file else {
        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .state_dir(CfgPath::new_literal(&config.state_dir))
            .cache_dir(CfgPath::new_literal(&config.cache_dir));
        builder
            .storage()
            .keystore()
            .primary()
            .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
        return Ok(LoadedArtiConfig {
            config: builder
                .build()
                .context("build default Arti configuration")?,
            state_dir: config.state_dir.clone(),
            cache_dir: config.cache_dir.clone(),
        });
    };

    let encoded = fs::read_to_string(path)
        .with_context(|| format!("read Arti configuration {}", path.display()))?;
    let mut document: toml::Value = toml::from_str(&encoded)
        .with_context(|| format!("parse Arti configuration {}", path.display()))?;
    let root = document
        .as_table_mut()
        .context("Arti configuration root must be a table")?;
    let storage = table_entry(root, "storage")?;
    let state_dir = configured_or_default_path(storage, "state_dir", &config.state_dir)?;
    let cache_dir = configured_or_default_path(storage, "cache_dir", &config.cache_dir)?;
    if state_dir == cache_dir {
        bail!("Arti state_dir and cache_dir must be distinct");
    }
    let keystore = table_entry(storage, "keystore")?;
    let primary = table_entry(keystore, "primary")?;
    if let Some(kind) = primary.get("kind")
        && kind.as_str() != Some("ephemeral")
    {
        bail!("Arti primary keystore must be ephemeral");
    }
    primary.insert(
        "kind".to_owned(),
        toml::Value::String("ephemeral".to_owned()),
    );

    let rendered = toml::to_string(&document).context("render effective Arti configuration")?;
    let mut sources = ConfigurationSources::new_empty();
    sources.push_source(
        ConfigurationSource::from_verbatim(rendered),
        MustRead::MustRead,
    );
    let tree = sources
        .load()
        .with_context(|| format!("load Arti configuration {}", path.display()))?;
    let resolved = tor_config::resolve(tree)
        .with_context(|| format!("resolve Arti configuration {}", path.display()))?;
    Ok(LoadedArtiConfig {
        config: resolved,
        state_dir,
        cache_dir,
    })
}

fn table_entry<'a>(
    parent: &'a mut toml::map::Map<String, toml::Value>,
    name: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>> {
    let entry = parent
        .entry(name.to_owned())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    entry
        .as_table_mut()
        .with_context(|| format!("Arti configuration [{name}] must be a table"))
}

fn configured_or_default_path(
    storage: &mut toml::map::Map<String, toml::Value>,
    name: &str,
    default: &Path,
) -> Result<PathBuf> {
    let Some(value) = storage.get(name) else {
        let text = default
            .to_str()
            .context("default Arti storage path is not valid UTF-8")?
            .to_owned();
        storage.insert(name.to_owned(), toml::Value::String(text));
        return Ok(default.to_path_buf());
    };
    let text = value
        .as_str()
        .with_context(|| format!("Arti storage.{name} must be a path string"))?;
    CfgPath::new(text.to_owned())
        .path(&arti_client_base_resolver())
        .with_context(|| format!("expand Arti storage.{name}"))
}

fn prepare_private_directory(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            bail!("{label} path must be a directory, not a symlink or file")
        }
        #[cfg(unix)]
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } {
                bail!("{label} directory must be owned by the current user");
            }
        }
        #[cfg(not(unix))]
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create {label} directory {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make {label} directory private {}", path.display()))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)
        .with_context(|| format!("create {label} directory {}", path.display()))?;
    Ok(())
}

fn lock_tor_state(state_dir: &Path) -> Result<File> {
    let path = state_dir.join("mutualbackup.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("open Tor state lock {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("Tor state lock must be a regular file");
    }
    file.try_lock_exclusive().with_context(|| {
        format!(
            "Tor state directory is already in use: {}",
            state_dir.display()
        )
    })?;
    Ok(file)
}

fn validate_onion_service_state(state_dir: &Path) -> Result<()> {
    for component in ["hss", "state", "hss_iptreplay"] {
        let parent = state_dir.join(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                bail!(
                    "Arti state component must be a directory: {}",
                    parent.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn onion_listener_address(node_id: NodeId) -> Result<Multiaddr> {
    let hostname = node_id.onion_hostname();
    let host = hostname
        .strip_suffix(".onion")
        .expect("Node ID onion hostname has the canonical suffix");
    format!("/onion3/{host}:{ONION_SERVICE_PORT}")
        .parse()
        .context("construct onion multiaddress")
}

fn anonymous_inbound_address() -> Multiaddr {
    Multiaddr::empty()
}

fn parse_onion_target(address: &Multiaddr) -> Option<(String, u16)> {
    let (hostname, port, _) = parse_canonical_onion_endpoint(address)?;
    Some((hostname, port))
}

fn parse_canonical_onion_endpoint(
    address: &Multiaddr,
) -> Option<(String, u16, Option<libp2p::PeerId>)> {
    let mut protocols = address.iter();
    let Protocol::Onion3(onion) = protocols.next()? else {
        return None;
    };
    if onion.port() != ONION_SERVICE_PORT {
        return None;
    }
    let terminal_peer = match protocols.next() {
        None => None,
        Some(Protocol::P2p(peer)) if protocols.next().is_none() => Some(peer),
        _ => return None,
    };
    let hostname = format!(
        "{}.onion",
        BASE32_NOPAD.encode(onion.hash()).to_ascii_lowercase()
    );
    hostname.parse::<HsId>().ok()?;
    let onion_peer = peer_id_from_onion_hash(onion.hash())?;
    if terminal_peer.is_some_and(|peer| peer != onion_peer) {
        return None;
    }
    Some((hostname, onion.port(), terminal_peer))
}

fn peer_id_from_onion_hash(hash: &[u8; 35]) -> Option<libp2p::PeerId> {
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&hash[..32]).ok()?;
    Some(libp2p::identity::PublicKey::from(public).to_peer_id())
}

pub fn is_onion_address(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::Onion3(_)))
}

pub fn is_canonical_onion_address(address: &Multiaddr) -> bool {
    parse_canonical_onion_endpoint(address).is_some()
}

pub fn onion_address_matches_node(address: &Multiaddr, node_id: NodeId) -> bool {
    if !is_onion_address(address) {
        return true;
    }
    parse_canonical_onion_endpoint(address)
        .is_some_and(|(hostname, _, _)| hostname == node_id.onion_hostname())
}

pub fn onion_address_matches_peer(address: &Multiaddr, peer: libp2p::PeerId) -> bool {
    if !is_onion_address(address) {
        return true;
    }
    let mut protocols = address.iter();
    let Some(Protocol::Onion3(onion)) = protocols.next() else {
        return false;
    };
    parse_canonical_onion_endpoint(address).is_some()
        && peer_id_from_onion_hash(onion.hash()) == Some(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{KeyMaterial, Seed};

    #[test]
    fn onion_multiaddress_is_bound_to_node_identity() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        let address = onion_listener_address(keys.node_id()).unwrap();
        assert!(is_onion_address(&address));
        assert!(onion_address_matches_node(&address, keys.node_id()));
        assert_eq!(
            parse_onion_target(&address).unwrap().0,
            keys.onion_hostname()
        );
        assert!(!onion_address_matches_node(
            &address,
            KeyMaterial::from_seed(&Seed::from_bytes([8; 32])).node_id()
        ));
    }

    #[test]
    fn onion_dial_target_accepts_only_an_optional_terminal_peer_id() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([9; 32]));
        let bare = onion_listener_address(keys.node_id()).unwrap();
        let peer = keys.node_id().libp2p_peer_id().unwrap();
        let with_peer: Multiaddr = format!("{bare}/p2p/{peer}").parse().unwrap();
        assert_eq!(parse_onion_target(&bare), parse_onion_target(&with_peer));

        let with_suffix: Multiaddr = format!("{bare}/p2p/{peer}/p2p-circuit").parse().unwrap();
        assert!(parse_onion_target(&with_suffix).is_none());

        let other_peer = KeyMaterial::from_seed(&Seed::from_bytes([10; 32]))
            .node_id()
            .libp2p_peer_id()
            .unwrap();
        let mismatched_peer: Multiaddr = format!("{bare}/p2p/{other_peer}").parse().unwrap();
        assert!(parse_onion_target(&mismatched_peer).is_none());
    }

    #[test]
    fn onion_endpoint_rejects_corrupt_v3_bytes_and_wrong_port() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([11; 32]));
        let valid = onion_listener_address(keys.node_id()).unwrap();
        let Protocol::Onion3(onion) = valid.iter().next().unwrap() else {
            panic!("generated address is not onion3");
        };

        for index in [32, 34] {
            let mut corrupt = *onion.hash();
            corrupt[index] ^= 1;
            let address =
                Multiaddr::empty().with(Protocol::Onion3((corrupt, ONION_SERVICE_PORT).into()));
            assert!(parse_onion_target(&address).is_none());
            assert!(!onion_address_matches_node(&address, keys.node_id()));
            assert!(!onion_address_matches_peer(
                &address,
                keys.node_id().libp2p_peer_id().unwrap()
            ));
        }

        let wrong_port = Multiaddr::empty().with(Protocol::Onion3(
            ((*onion.hash()), ONION_SERVICE_PORT + 1).into(),
        ));
        assert!(parse_onion_target(&wrong_port).is_none());
        assert!(!onion_address_matches_node(&wrong_port, keys.node_id()));

        let prefixed = Multiaddr::empty()
            .with(Protocol::Memory(7))
            .with(Protocol::Onion3(
                ((*onion.hash()), ONION_SERVICE_PORT).into(),
            ));
        assert!(!onion_address_matches_node(&prefixed, keys.node_id()));
    }

    #[test]
    fn anonymous_inbound_address_is_not_the_onion_listener() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([12; 32]));
        let listener = onion_listener_address(keys.node_id()).unwrap();
        let remote = anonymous_inbound_address();
        assert!(remote.is_empty());
        assert_ne!(remote, listener);
    }

    #[test]
    fn tor_mode_text_is_stable() {
        for (text, mode) in [
            ("auto", TorMode::Auto),
            ("prefer-tor", TorMode::PreferTor),
            ("require-tor", TorMode::RequireTor),
            ("disable-tor", TorMode::DisableTor),
        ] {
            assert_eq!(text.parse::<TorMode>().unwrap(), mode);
            assert_eq!(mode.to_string(), text);
        }
        assert!("sometimes".parse::<TorMode>().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn preparation_preserves_service_state() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        prepare_private_directory(&state, "test").unwrap();
        let ours = state.join("hss").join(ONION_SERVICE_NICKNAME);
        let other = state.join("hss").join("another-service");
        fs::create_dir_all(&ours).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(ours.join("ipts.json"), b"stale").unwrap();
        fs::write(other.join("ipts.json"), b"keep").unwrap();
        validate_onion_service_state(&state).unwrap();
        assert!(ours.join("ipts.json").exists());
        assert!(other.join("ipts.json").exists());
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn state_lock_excludes_another_daemon_and_state_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        prepare_private_directory(&state, "test").unwrap();
        let first = lock_tor_state(&state).unwrap();
        assert!(lock_tor_state(&state).is_err());
        drop(first);
        lock_tor_state(&state).unwrap();

        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, state.join("hss")).unwrap();
        assert!(validate_onion_service_state(&state).is_err());
        assert!(outside.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_wait_observes_arti_instance_lock_release() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let hss = state.join("hss");
        fs::create_dir_all(&hss).unwrap();
        let path = hss.join(format!("{ONION_SERVICE_NICKNAME}.lock"));
        let file = File::create(path).unwrap();
        file.try_lock_exclusive().unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(file);
        });
        wait_for_onion_service_shutdown(&state).await.unwrap();
        release.await.unwrap();
    }
}
