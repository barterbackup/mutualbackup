//! Port mapping client and service.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};

use current_mapping::CurrentMapping;
use n0_error::{e, stack_error};
use n0_future::StreamExt;
use netwatch::interfaces::HomeRouter;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, debug, info_span, trace};

mod current_mapping;
mod mapping;
mod metrics;
mod nat_pmp;
mod pcp;
mod upnp;
mod util;
mod defaults {
    use std::time::Duration;

    /// Maximum duration a UPnP search can take before timing out.
    pub(crate) const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(1);

    /// Timeout to receive a response from a PCP server.
    pub(crate) const PCP_RECV_TIMEOUT: Duration = Duration::from_millis(500);

    /// Timeout to receive a response from a NAT-PMP server.
    pub(crate) const NAT_PMP_RECV_TIMEOUT: Duration = Duration::from_millis(500);
}

pub use metrics::Metrics;

/// If a port mapping service has been seen within the last [`AVAILABILITY_TRUST_DURATION`] it will
/// not be probed again.
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

/// Capacity of the channel to communicate with the long-running service.
const SERVICE_CHANNEL_CAPACITY: usize = 32; // should be plenty

/// If a port mapping service has not been seen within the last [`UNAVAILABILITY_TRUST_DURATION`]
/// we allow trying a mapping using said protocol.
const UNAVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(5);

/// Output of a port mapping probe.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("portmap={{ UPnP: {upnp}, PMP: {nat_pmp}, PCP: {pcp} }}")]
pub struct ProbeOutput {
    /// If UPnP can be considered available.
    pub upnp: bool,
    /// If PCP can be considered available.
    pub pcp: bool,
    /// If PMP can be considered available.
    pub nat_pmp: bool,
}

impl ProbeOutput {
    /// Indicates if all port mapping protocols are available.
    pub fn all_available(&self) -> bool {
        self.upnp && self.pcp && self.nat_pmp
    }
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[derive(Clone)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("Mapping channel is full")]
    ChannelFull,
    #[error("Mapping channel is closed")]
    ChannelClosed,
    #[error("No gateway found for probe")]
    NoGateway,
    #[error("gateway found is ipv6, ignoring")]
    Ipv6Gateway,
    #[error("Probe task stopped. is_panic: {is_panic}, is_cancelled: {is_cancelled}")]
    Join { is_panic: bool, is_cancelled: bool },
}

/// Error returned by [`Client::deactivate_and_wait`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeactivateError {
    /// The background service stopped before acknowledging deactivation.
    ServiceStopped,
    /// A granted mapping could not be released.
    Release(String),
}

impl std::fmt::Display for DeactivateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceStopped => formatter.write_str("port-mapping service stopped"),
            Self::Release(error) => write!(formatter, "failed to release port mapping: {error}"),
        }
    }
}

impl std::error::Error for DeactivateError {}

#[derive(derive_more::Debug)]
enum Message {
    /// Attempt to get a mapping if the local port is set but there is no mapping.
    ProcureMapping,
    /// Request to update the local port.
    ///
    /// The resulting external address can be obtained subscribing using
    /// [`Client::watch_external_address`].
    /// A value of `None` will deactivate port mapping.
    UpdateLocalPort { local_port: Option<NonZeroU16> },
    /// Deactivate port mapping and acknowledge release of the active lease and
    /// any lease returned by an in-flight acquisition.
    Deactivate {
        #[debug("_")]
        result_tx: oneshot::Sender<Result<(), String>>,
    },
    /// Request to probe the port mapping protocols.
    ///
    /// The requester should wait for the result at the [`oneshot::Receiver`] counterpart of the
    /// [`oneshot::Sender`].
    Probe {
        /// Sender side to communicate the result of the probe.
        #[debug("_")]
        result_tx: oneshot::Sender<Result<ProbeOutput, ProbeError>>,
    },
}

/// Configuration for UDP or TCP network protocol.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    /// UDP protocol.
    Udp,
    /// TCP protocol.
    Tcp,
}

/// Configures which port mapping protocols are enabled in the [`Service`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether UPnP is enabled.
    pub enable_upnp: bool,
    /// Whether PCP is enabled.
    pub enable_pcp: bool,
    /// Whether PMP is enabled.
    pub enable_nat_pmp: bool,
    /// Whether to use UDP or TCP.
    pub protocol: Protocol,
}

impl Default for Config {
    /// By default all port mapping protocols are enabled for UDP.
    fn default() -> Self {
        Config {
            enable_upnp: true,
            enable_pcp: true,
            enable_nat_pmp: true,
            protocol: Protocol::Udp,
        }
    }
}

/// Port mapping client.
#[derive(Debug, Clone)]
pub struct Client {
    /// A watcher over the most recent external address obtained from port mapping.
    ///
    /// See [`watch::Receiver`].
    port_mapping: watch::Receiver<Option<SocketAddrV4>>,
    /// Channel used to communicate with the port mapping service.
    service_tx: mpsc::Sender<Message>,
    /// Metrics collected by the service.
    metrics: Arc<Metrics>,
    /// A handle to the service that will cancel the spawned task once the client is dropped.
    _service_handle: std::sync::Arc<AbortOnDropHandle<()>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Client {
    /// Create a new port mapping client.
    pub fn new(config: Config) -> Self {
        Self::with_metrics(config, Default::default())
    }

    /// Creates a new port mapping client with a previously created metrics collector.
    pub fn with_metrics(config: Config, metrics: Arc<Metrics>) -> Self {
        let (service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);

        let (service, watcher) = Service::new(config, service_rx, metrics.clone());

        let handle = AbortOnDropHandle::new(tokio::spawn(
            async move { service.run().await }.instrument(info_span!("portmapper.service")),
        ));

        Client {
            port_mapping: watcher,
            service_tx,
            metrics,
            _service_handle: std::sync::Arc::new(handle),
        }
    }

    /// Request a probe to the port mapping protocols.
    ///
    /// Returns the [`oneshot::Receiver`] used to obtain the result of the probe.
    pub fn probe(&self) -> oneshot::Receiver<Result<ProbeOutput, ProbeError>> {
        let (result_tx, result_rx) = oneshot::channel();

        if let Err(e) = self.service_tx.try_send(Message::Probe { result_tx }) {
            use mpsc::error::TrySendError::*;

            // recover the sender and return the error there
            let (result_tx, e) = match e {
                Full(Message::Probe { result_tx }) => (result_tx, e!(ProbeError::ChannelFull)),
                Closed(Message::Probe { result_tx }) => (result_tx, e!(ProbeError::ChannelClosed)),
                Full(_) | Closed(_) => unreachable!("Sent value is a probe."),
            };

            // sender was just created. If it's dropped we have two send error and are likely
            // shutting down
            // NOTE: second Err is infallible match due to being the sent value
            if let Err(Err(e)) = result_tx.send(Err(e)) {
                trace!("Failed to request probe: {e}")
            }
        }
        result_rx
    }

    /// Try to get a mapping for the last local port if there isn't one already.
    pub fn procure_mapping(&self) {
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self.service_tx.try_send(Message::ProcureMapping) {
            trace!("Failed to request mapping {e}")
        }
    }

    /// Update the local port.
    ///
    /// If the port changes, this will trigger a port mapping attempt.
    pub fn update_local_port(&self, local_port: NonZeroU16) {
        let local_port = Some(local_port);
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self
            .service_tx
            .try_send(Message::UpdateLocalPort { local_port })
        {
            trace!("Failed to update local port {e}")
        }
    }

    /// Deactivate port mapping.
    pub fn deactivate(&self) {
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self
            .service_tx
            .try_send(Message::UpdateLocalPort { local_port: None })
        {
            trace!("Failed to deactivate port mapping {e}")
        }
    }

    /// Deactivate port mapping and wait for the active mapping and any in-flight
    /// acquisition to be settled. Callers that need a bounded shutdown must
    /// apply their own timeout and treat expiration as incomplete cleanup.
    pub async fn deactivate_and_wait(&self) -> Result<(), DeactivateError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.service_tx
            .send(Message::Deactivate { result_tx })
            .await
            .map_err(|_| DeactivateError::ServiceStopped)?;
        result_rx
            .await
            .map_err(|_| DeactivateError::ServiceStopped)?
            .map_err(DeactivateError::Release)
    }

    /// Watch the external address for changes in the mappings.
    pub fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        self.port_mapping.clone()
    }

    /// Returns the metrics collected by the service.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
}

/// Port mapping protocol information obtained during a probe.
#[derive(Debug)]
struct Probe {
    /// When was the probe last updated.
    last_probe: Instant,
    /// The last [`upnp::Gateway`] and when was it last seen.
    last_upnp_gateway_addr: Option<(upnp::Gateway, Instant)>,
    /// Last time PCP was seen.
    last_pcp: Option<Instant>,
    /// Last time NAT-PMP was seen.
    last_nat_pmp: Option<Instant>,
}

impl Probe {
    /// An empty probe set to `now`.
    fn empty() -> Self {
        Self {
            last_probe: Instant::now(),
            last_upnp_gateway_addr: None,
            last_pcp: None,
            last_nat_pmp: None,
        }
    }
    /// Create a new probe based on a previous output.
    async fn from_output(
        config: Config,
        output: ProbeOutput,
        local_ip: Ipv4Addr,
        gateway: Ipv4Addr,
        metrics: Arc<Metrics>,
    ) -> Probe {
        let ProbeOutput { upnp, pcp, nat_pmp } = output;
        let Config {
            enable_upnp,
            enable_pcp,
            enable_nat_pmp,
            protocol: _,
        } = config;
        let mut upnp_probing_task = util::MaybeFuture {
            inner: (enable_upnp && !upnp).then(|| {
                let metrics = metrics.clone();
                Box::pin(async move {
                    upnp::probe_available(&metrics)
                        .await
                        .map(|addr| (addr, Instant::now()))
                })
            }),
        };

        let mut pcp_probing_task = util::MaybeFuture {
            inner: (enable_pcp && !pcp).then(|| {
                let metrics = metrics.clone();
                Box::pin(async move {
                    metrics.pcp_probes.inc();
                    pcp::probe_available(local_ip, gateway)
                        .await
                        .then(Instant::now)
                })
            }),
        };

        let mut nat_pmp_probing_task = util::MaybeFuture {
            inner: (enable_nat_pmp && !nat_pmp).then(|| {
                Box::pin(async {
                    nat_pmp::probe_available(local_ip, gateway)
                        .await
                        .then(Instant::now)
                })
            }),
        };

        if upnp_probing_task.inner.is_some() {
            metrics.upnp_probes.inc();
        }

        let mut upnp_done = upnp_probing_task.inner.is_none();
        let mut pcp_done = pcp_probing_task.inner.is_none();
        let mut nat_pmp_done = nat_pmp_probing_task.inner.is_none();

        let mut probe = Probe::empty();

        while !upnp_done || !pcp_done || !nat_pmp_done {
            tokio::select! {
                last_upnp_gateway_addr = &mut upnp_probing_task, if !upnp_done => {
                    trace!("tick: upnp probe ready");
                    probe.last_upnp_gateway_addr = last_upnp_gateway_addr;
                    upnp_done = true;
                },
                last_nat_pmp = &mut nat_pmp_probing_task, if !nat_pmp_done => {
                    trace!("tick: nat_pmp probe ready");
                    probe.last_nat_pmp = last_nat_pmp;
                    nat_pmp_done = true;
                },
                last_pcp = &mut pcp_probing_task, if !pcp_done => {
                    trace!("tick: pcp probe ready");
                    probe.last_pcp = last_pcp;
                    pcp_done = true;
                },
            }
        }

        probe
    }

    /// Returns a [`ProbeOutput`] indicating which services can be considered available.
    fn output(&self) -> ProbeOutput {
        let now = Instant::now();

        // check if the last UPnP gateway is valid
        let upnp = self
            .last_upnp_gateway_addr
            .as_ref()
            .map(|(_gateway_addr, last_probed)| *last_probed + AVAILABILITY_TRUST_DURATION > now)
            .unwrap_or_default();

        let pcp = self
            .last_pcp
            .as_ref()
            .map(|last_probed| *last_probed + AVAILABILITY_TRUST_DURATION > now)
            .unwrap_or_default();

        let nat_pmp = self
            .last_nat_pmp
            .as_ref()
            .map(|last_probed| *last_probed + AVAILABILITY_TRUST_DURATION > now)
            .unwrap_or_default();

        ProbeOutput { upnp, pcp, nat_pmp }
    }

    /// Updates a probe with the `Some` values of another probe that is _assumed_ newer.
    fn update(&mut self, probe: Probe, metrics: &Arc<Metrics>) {
        let Probe {
            last_probe,
            last_upnp_gateway_addr,
            last_pcp,
            last_nat_pmp,
        } = probe;
        if last_upnp_gateway_addr.is_some() {
            metrics.upnp_available.inc();
            let new_gateway = last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            let old_gateway = self
                .last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            if new_gateway != old_gateway {
                metrics.upnp_gateway_updated.inc();
                debug!(
                    "upnp gateway changed {:?} -> {:?}",
                    old_gateway
                        .map(|gw| gw.to_string())
                        .unwrap_or("None".into()),
                    new_gateway
                        .map(|gw| gw.to_string())
                        .unwrap_or("None".into())
                )
            };
            self.last_upnp_gateway_addr = last_upnp_gateway_addr;
        }
        if last_pcp.is_some() {
            metrics.pcp_available.inc();
            self.last_pcp = last_pcp;
        }
        if last_nat_pmp.is_some() {
            self.last_nat_pmp = last_nat_pmp;
        }

        self.last_probe = last_probe;
    }
}

// mainly to make clippy happy
type ProbeResult = Result<ProbeOutput, ProbeError>;

/// A port mapping client.
#[derive(Debug)]
pub struct Service {
    config: Config,
    /// Local port to map.
    local_port: Option<NonZeroU16>,
    /// Channel over which the service is informed of messages.
    ///
    /// The service will stop when all senders are gone.
    rx: mpsc::Receiver<Message>,
    /// Currently active mapping.
    current_mapping: CurrentMapping,
    /// Last updated probe.
    full_probe: Probe,
    /// Task attempting to get a port mapping.
    ///
    /// A request to change the local port releases the active mapping, then
    /// settles this task before acknowledging the change.
    mapping_task: Option<AbortOnDropHandle<Result<mapping::Mapping, mapping::Error>>>,
    /// Task probing the necessary protocols.
    ///
    /// Requests for a probe that arrive while this task is still in progress will receive the same
    /// result.
    probing_task: Option<(AbortOnDropHandle<Probe>, Vec<oneshot::Sender<ProbeResult>>)>,
    /// First failure while releasing a lease superseded by a successful
    /// replacement. Preserve it until an acknowledged port change can report
    /// that cleanup was incomplete.
    mapping_release_error: Option<mapping::Error>,
    metrics: Arc<Metrics>,
}

impl Service {
    fn new(
        config: Config,
        rx: mpsc::Receiver<Message>,
        metrics: Arc<Metrics>,
    ) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let (current_mapping, watcher) = CurrentMapping::new(metrics.clone());
        let mut full_probe = Probe::empty();
        if let Some(in_the_past) = full_probe
            .last_probe
            .checked_sub(AVAILABILITY_TRUST_DURATION)
        {
            // we want to do a first full probe, so set is as expired on start-up
            full_probe.last_probe = in_the_past;
        }
        let service = Service {
            config,
            local_port: None,
            rx,
            current_mapping,
            full_probe,
            mapping_task: None,
            probing_task: None,
            mapping_release_error: None,
            metrics,
        };

        (service, watcher)
    }

    /// Clears the current mapping and releases it.
    async fn invalidate_mapping(&mut self) -> Result<(), mapping::Error> {
        if let Some(old_mapping) = self.current_mapping.update(None) {
            old_mapping.release().await?;
        }
        Ok(())
    }

    /// Settle an acquisition after withdrawing the known active lease. A
    /// successful task may already hold a gateway lease even though `run` has
    /// not selected its completion branch yet, so deactivation must retain and
    /// await the handle before it can acknowledge complete cleanup.
    async fn settle_mapping_task(&mut self) -> Result<(), mapping::Error> {
        let Some(task) = self.mapping_task.take() else {
            return Ok(());
        };
        release_mapping_task_result(task.await, &self.metrics).await
    }

    async fn run(mut self) {
        debug!("portmap starting");
        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    trace!("tick: msg {msg:?}");
                    match msg {
                        Some(msg) => {
                            self.handle_msg(msg).await;
                        },
                        None => {
                            debug!("portmap service channel dropped. Likely shutting down.");
                            break;
                        }
                    }
                }
                mapping_result = util::MaybeFuture{ inner: self.mapping_task.as_mut() } => {
                    trace!("tick: mapping ready");
                    // regardless of outcome, the task is finished, clear it
                    self.mapping_task = None;
                    // there isn't really a way to react to a join error here. Flatten it to make
                    // it easier to work with
                    self.on_mapping_result(mapping_result).await;
                }
                probe_result = util::MaybeFuture{ inner: self.probing_task.as_mut().map(|(fut, _rec)| fut) } => {
                    trace!("tick: probe ready");
                    // retrieve the receivers and clear the task
                    let receivers = self.probing_task.take().expect("is some").1;
                    let probe_result = probe_result.map_err(|e| e!(ProbeError::Join { is_panic: e.is_panic(), is_cancelled: e.is_cancelled() }));
                    self.on_probe_result(probe_result, receivers);
                }
                Some(event) = self.current_mapping.next() => {
                    trace!("tick: mapping event {event:?}");
                    match event {
                        current_mapping::Event::Renew { external_ip, external_port } | current_mapping::Event::Expired { external_ip, external_port } => {
                            self.get_mapping(Some((external_ip, external_port)));
                        },
                    }

                }
            }
        }
    }

    fn on_probe_result(
        &mut self,
        result: Result<Probe, ProbeError>,
        receivers: Vec<oneshot::Sender<ProbeResult>>,
    ) {
        let result = result.map(|probe| {
            self.full_probe.update(probe, &self.metrics);
            // TODO(@divma): the gateway of the current mapping could have changed. Tailscale
            // still assumes the current mapping is valid/active and will return it even after
            // this
            let output = self.full_probe.output();
            trace!(?output, "probe output");
            output
        });
        for tx in receivers {
            // ignore the error. If the receiver is no longer there we don't really care
            let _ = tx.send(result.clone());
        }
    }

    async fn on_mapping_result(
        &mut self,
        result: Result<Result<mapping::Mapping, mapping::Error>, tokio::task::JoinError>,
    ) {
        match result {
            Ok(Ok(mapping)) => {
                let same_lease = self
                    .current_mapping
                    .mapping()
                    .is_some_and(|current| current.same_lease(&mapping));
                let superseded = self.current_mapping.update(Some(mapping));
                if !same_lease
                    && let Some(superseded) = superseded
                    && let Err(error) = superseded.release().await
                {
                    debug!("failed to release superseded port mapping {error}");
                    self.metrics.mapping_failures.inc();
                    if self.mapping_release_error.is_none() {
                        self.mapping_release_error = Some(error);
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("failed to get a port mapping {e}");
                self.metrics.mapping_failures.inc();
            }
            Err(e) => {
                debug!("failed to get a port mapping {e}");
                self.metrics.mapping_failures.inc();
            }
        }
    }

    async fn handle_msg(&mut self, msg: Message) {
        match msg {
            Message::ProcureMapping => {
                if let Err(e) = self.update_local_port(self.local_port).await {
                    debug!("failed to release superseded mapping {e}");
                }
            }
            Message::UpdateLocalPort { local_port } => {
                if let Err(e) = self.update_local_port(local_port).await {
                    debug!("failed to release superseded mapping {e}");
                }
            }
            Message::Deactivate { result_tx } => {
                let result = self
                    .update_local_port(None)
                    .await
                    .map_err(|error| error.to_string());
                let _ = result_tx.send(result);
            }
            Message::Probe { result_tx } => self.probe_request(result_tx),
        }
    }

    /// Updates the local port of the port mapping service.
    ///
    /// If the port changed, any port mapping task is settled and a granted
    /// mapping is released. If the new port is some, this starts a new task.
    async fn update_local_port(
        &mut self,
        local_port: Option<NonZeroU16>,
    ) -> Result<(), mapping::Error> {
        // ignore requests to update the local port in a way that does not produce a change
        if local_port != self.local_port {
            self.metrics.local_port_updates.inc();
            let old_port = std::mem::replace(&mut self.local_port, local_port);
            // get the current external port if any to try to get it again
            let external_addr = self.current_mapping.external();

            // Withdraw and release the known active lease before waiting for a
            // renewal attempt, which may be stalled in a gateway request.
            let mut release_error = self.mapping_release_error.take();
            if let Err(error) = self.invalidate_mapping().await
                && release_error.is_none()
            {
                release_error = Some(error);
            }
            if let Err(error) = self.settle_mapping_task().await
                && release_error.is_none()
            {
                release_error = Some(error);
            }
            debug!(
                "settled mapping state due to local port update. Old: {:?} New: {:?}",
                old_port, self.local_port
            );

            // start a new mapping task to account for the new port if necessary
            self.get_mapping(external_addr);
            if let Some(error) = release_error {
                return Err(error);
            }
        } else if self.current_mapping.external().is_none() {
            // if the local port has not changed, but there is no active mapping try to get one
            self.get_mapping(None)
        }
        Ok(())
    }

    fn get_mapping(&mut self, external_addr: Option<(Ipv4Addr, NonZeroU16)>) {
        if self.mapping_task.is_some() {
            return;
        }
        if let Some(local_port) = self.local_port {
            self.metrics.mapping_attempts.inc();

            let (local_ip, gateway) = match ip_and_gateway() {
                Ok(ip_and_gw) => ip_and_gw,
                Err(e) => return debug!("can't get mapping: {e}"),
            };

            let ProbeOutput { upnp, pcp, nat_pmp } = self.full_probe.output();

            debug!("getting a port mapping for {local_ip}:{local_port} -> {external_addr:?}");
            let recently_probed =
                self.full_probe.last_probe + UNAVAILABILITY_TRUST_DURATION > Instant::now();
            let protocol = self.config.protocol;
            // strategy:
            // 1. check the available services and prefer pcp, then nat_pmp then upnp since it's
            //    the most unreliable, but possibly the most deployed one
            // 2. if no service was available, fallback to upnp if enabled, followed by pcp and
            //    nat_pmp
            self.mapping_task = if pcp {
                // try pcp if available first
                let task = mapping::Mapping::new_pcp(
                    protocol,
                    local_ip,
                    local_port,
                    gateway,
                    external_addr,
                );
                Some(AbortOnDropHandle::new(tokio::spawn(
                    task.instrument(info_span!("pcp")),
                )))
            } else if nat_pmp {
                // next nat_pmp if available
                let task = mapping::Mapping::new_nat_pmp(
                    protocol,
                    local_ip,
                    local_port,
                    gateway,
                    external_addr,
                );
                Some(AbortOnDropHandle::new(tokio::spawn(
                    task.instrument(info_span!("pmp")),
                )))
            } else if upnp || self.config.enable_upnp {
                // next upnp if available or enabled
                let external_port = external_addr.map(|(_addr, port)| port);
                let gateway = self
                    .full_probe
                    .last_upnp_gateway_addr
                    .as_ref()
                    .map(|(gateway, _last_seen)| gateway.clone());
                let task = mapping::Mapping::new_upnp(
                    protocol,
                    local_ip,
                    local_port,
                    gateway,
                    external_port,
                );

                Some(AbortOnDropHandle::new(tokio::spawn(
                    task.instrument(info_span!("upnp")),
                )))
            } else if !recently_probed && self.config.enable_pcp {
                // if no service is available and the default fallback (upnp) is disabled, try pcp
                // first
                let task = mapping::Mapping::new_pcp(
                    protocol,
                    local_ip,
                    local_port,
                    gateway,
                    external_addr,
                );

                Some(AbortOnDropHandle::new(tokio::spawn(
                    task.instrument(info_span!("pcp")),
                )))
            } else if !recently_probed && self.config.enable_nat_pmp {
                // finally try nat_pmp if enabled
                let task = mapping::Mapping::new_nat_pmp(
                    protocol,
                    local_ip,
                    local_port,
                    gateway,
                    external_addr,
                );
                Some(AbortOnDropHandle::new(tokio::spawn(
                    task.instrument(info_span!("pmp")),
                )))
            } else {
                // give up
                return;
            }
        }
    }

    /// Handles a probe request.
    ///
    /// If there is a task getting a probe, the receiver will be added with any other waiting for a
    /// result. If no probe is underway, a result can be returned immediately if it's still
    /// considered valid. Otherwise, a new probe task will be started.
    fn probe_request(&mut self, result_tx: oneshot::Sender<Result<ProbeOutput, ProbeError>>) {
        match self.probing_task.as_mut() {
            Some((_task_handle, receivers)) => receivers.push(result_tx),
            None => {
                let probe_output = self.full_probe.output();
                if probe_output.all_available() {
                    // we don't care if the requester is no longer there
                    let _ = result_tx.send(Ok(probe_output));
                } else {
                    self.metrics.probes_started.inc();

                    let (local_ip, gateway) = match ip_and_gateway() {
                        Ok(ip_and_gw) => ip_and_gw,
                        Err(e) => {
                            // there is no guarantee this will be displayed, so log it anyway
                            debug!("could not start probe: {e}");
                            let _ = result_tx.send(Err(e));
                            return;
                        }
                    };

                    let config = self.config.clone();
                    let metrics = self.metrics.clone();
                    let handle = tokio::spawn(
                        async move {
                            Probe::from_output(config, probe_output, local_ip, gateway, metrics)
                                .await
                        }
                        .instrument(info_span!("portmapper.probe")),
                    );
                    let receivers = vec![result_tx];
                    self.probing_task = Some((AbortOnDropHandle::new(handle), receivers));
                }
            }
        }
    }
}

async fn release_mapping_task_result(
    result: Result<Result<mapping::Mapping, mapping::Error>, tokio::task::JoinError>,
    metrics: &Metrics,
) -> Result<(), mapping::Error> {
    match result {
        Ok(Ok(mapping)) => mapping.release().await,
        Ok(Err(error)) => {
            debug!("failed to get a port mapping {error}");
            metrics.mapping_failures.inc();
            Ok(())
        }
        Err(error) => {
            debug!("failed to get a port mapping {error}");
            metrics.mapping_failures.inc();
            Ok(())
        }
    }
}

/// Gets the local ip and gateway address for port mapping.
fn ip_and_gateway() -> Result<(Ipv4Addr, Ipv4Addr), ProbeError> {
    let Some(HomeRouter { gateway, my_ip }) = HomeRouter::new() else {
        return Err(e!(ProbeError::NoGateway));
    };

    let local_ip = match my_ip {
        Some(std::net::IpAddr::V4(ip))
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() =>
        {
            ip
        }
        other => {
            debug!("no address suitable for port mapping found ({other:?}), using localhost");
            Ipv4Addr::LOCALHOST
        }
    };

    let std::net::IpAddr::V4(gateway) = gateway else {
        return Err(e!(ProbeError::Ipv6Gateway));
    };

    Ok((local_ip, gateway))
}
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn upnp_test_gateway(address: std::net::SocketAddr) -> upnp::Gateway {
        let mapping_arguments = [
            "NewRemoteHost",
            "NewExternalPort",
            "NewProtocol",
            "NewInternalPort",
            "NewInternalClient",
            "NewEnabled",
            "NewPortMappingDescription",
            "NewLeaseDuration",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let delete_arguments = ["NewRemoteHost", "NewExternalPort", "NewProtocol"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        upnp::Gateway {
            addr: address,
            root_url: "/".to_owned(),
            control_url: "/control".to_owned(),
            control_schema_url: "/schema".to_owned(),
            control_schema: std::collections::HashMap::from([
                ("AddPortMapping".to_owned(), mapping_arguments.clone()),
                ("AddAnyPortMapping".to_owned(), mapping_arguments),
                ("DeletePortMapping".to_owned(), delete_arguments),
            ]),
            provider: igd_next::aio::tokio::Tokio,
        }
    }

    async fn receive_upnp_request(
        listener: &tokio::net::TcpListener,
    ) -> (tokio::net::TcpStream, String) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0_u8; 2_048];
            let read = stream.read(&mut bytes).await.unwrap();
            assert_ne!(read, 0, "UPnP client closed before sending its request");
            request.extend_from_slice(&bytes[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        (stream, String::from_utf8(request).unwrap())
    }

    async fn respond_upnp(mut stream: tokio::net::TcpStream, action: &str, contents: &str) {
        let body = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{contents}</u:{action}></s:Body></s:Envelope>"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deactivation_releases_an_active_lease_before_a_stalled_renewal() {
        let gateway = Ipv4Addr::new(127, 0, 0, 3);
        let local_ip = Ipv4Addr::new(127, 0, 0, 4);
        let local_port = NonZeroU16::new(39_452).unwrap();
        let external_port = 45_001_u16;
        let gateway_socket = tokio::net::UdpSocket::bind((gateway, 5351)).await.unwrap();
        let (active_deleted_tx, active_deleted_rx) = oneshot::channel();
        let (renewed_deleted_tx, renewed_deleted_rx) = oneshot::channel();
        let gateway_task = tokio::spawn(async move {
            let mut active_deleted_tx = Some(active_deleted_tx);
            let mut renewed_deleted_tx = Some(renewed_deleted_tx);
            let mut packet = [0_u8; 64];
            for acquisition in 0..2 {
                let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..read], &[0, 0]);
                let mut public_response = vec![0, 128, 0, 0];
                public_response.extend_from_slice(&0_u32.to_be_bytes());
                public_response.extend_from_slice(&[198, 51, 100, 8]);
                gateway_socket
                    .send_to(&public_response, peer)
                    .await
                    .unwrap();

                let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(read, 12);
                assert_eq!(&packet[..4], &[0, 1, 0, 0]);
                assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), local_port.get());
                assert_ne!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 0);
                let mut mapping_response = vec![0, 129, 0, 0];
                mapping_response.extend_from_slice(&0_u32.to_be_bytes());
                mapping_response.extend_from_slice(&local_port.get().to_be_bytes());
                mapping_response.extend_from_slice(&external_port.to_be_bytes());
                mapping_response.extend_from_slice(&7_200_u32.to_be_bytes());
                gateway_socket
                    .send_to(&mapping_response, peer)
                    .await
                    .unwrap();

                let (read, _) = gateway_socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(read, 12);
                assert_eq!(&packet[..4], &[0, 1, 0, 0]);
                assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), local_port.get());
                assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
                assert_eq!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 0);
                if acquisition == 0 {
                    let _ = active_deleted_tx.take().unwrap().send(());
                } else {
                    let _ = renewed_deleted_tx.take().unwrap().send(());
                }
            }
        });

        let mapping =
            mapping::Mapping::new_nat_pmp(Protocol::Udp, local_ip, local_port, gateway, None)
                .await
                .unwrap();
        let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let (mut service, external) =
            Service::new(Config::default(), service_rx, Default::default());
        service.local_port = Some(local_port);
        service.current_mapping.update(Some(mapping));
        assert!(external.borrow().is_some());

        let (resume_tx, resume_rx) = oneshot::channel();
        let renewal = async move {
            let _ = resume_rx.await;
            mapping::Mapping::new_nat_pmp(
                Protocol::Udp,
                local_ip,
                local_port,
                gateway,
                Some((
                    Ipv4Addr::new(198, 51, 100, 8),
                    external_port.try_into().unwrap(),
                )),
            )
            .await
        };
        service.mapping_task = Some(AbortOnDropHandle::new(tokio::spawn(renewal)));

        let mut cleanup_task = tokio::spawn(async move { service.update_local_port(None).await });
        tokio::time::timeout(Duration::from_secs(1), active_deleted_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(external.borrow().is_none());
        assert!(!cleanup_task.is_finished());

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut cleanup_task)
                .await
                .is_err()
        );
        resume_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), cleanup_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), renewed_deleted_rx)
            .await
            .unwrap()
            .unwrap();
        gateway_task.await.unwrap();
    }

    #[tokio::test]
    async fn deactivation_releases_a_nat_pmp_lease_while_acquisition_is_paused_after_grant() {
        let gateway = Ipv4Addr::LOCALHOST;
        let local_ip = Ipv4Addr::new(127, 0, 0, 2);
        let local_port = NonZeroU16::new(39_451).unwrap();
        let external_port = 45_000_u16;
        let gateway_socket = tokio::net::UdpSocket::bind((gateway, 5351)).await.unwrap();
        let (deleted_tx, deleted_rx) = oneshot::channel();
        let gateway_task = tokio::spawn(async move {
            let mut packet = [0_u8; 64];

            let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..read], &[0, 0]);
            let mut public_response = vec![0, 128, 0, 0];
            public_response.extend_from_slice(&0_u32.to_be_bytes());
            public_response.extend_from_slice(&[198, 51, 100, 7]);
            gateway_socket
                .send_to(&public_response, peer)
                .await
                .unwrap();

            let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(read, 12);
            assert_eq!(&packet[..4], &[0, 1, 0, 0]);
            assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), local_port.get());
            assert_ne!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 0);
            let mut mapping_response = vec![0, 129, 0, 0];
            mapping_response.extend_from_slice(&0_u32.to_be_bytes());
            mapping_response.extend_from_slice(&local_port.get().to_be_bytes());
            mapping_response.extend_from_slice(&external_port.to_be_bytes());
            mapping_response.extend_from_slice(&7_200_u32.to_be_bytes());
            gateway_socket
                .send_to(&mapping_response, peer)
                .await
                .unwrap();

            let (read, _) = gateway_socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(read, 12);
            assert_eq!(&packet[..4], &[0, 1, 0, 0]);
            assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), local_port.get());
            assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
            assert_eq!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 0);
            let _ = deleted_tx.send(());
        });

        let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let (mut service, external) =
            Service::new(Config::default(), service_rx, Default::default());
        service.local_port = Some(local_port);
        let (granted_tx, granted_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let acquisition = async move {
            let mapping =
                mapping::Mapping::new_nat_pmp(Protocol::Udp, local_ip, local_port, gateway, None)
                    .await?;
            let _ = granted_tx.send(());
            let _ = resume_rx.await;
            Ok(mapping)
        };
        service.mapping_task = Some(AbortOnDropHandle::new(tokio::spawn(acquisition)));

        granted_rx.await.unwrap();
        let mut cleanup = Box::pin(service.update_local_port(None));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut cleanup)
                .await
                .is_err()
        );
        resume_tx.send(()).unwrap();
        cleanup.await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), deleted_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(external.borrow().is_none());
        gateway_task.await.unwrap();
    }

    #[tokio::test]
    async fn upnp_replacement_releases_both_distinct_leases_before_acknowledgement() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gateway = upnp_test_gateway(listener.local_addr().unwrap());
        let local_ip = Ipv4Addr::LOCALHOST;
        let local_port = NonZeroU16::new(39_500).unwrap();
        let first_port = 45_100_u16;
        let replacement_port = 45_101_u16;
        let (first_deleted_tx, first_deleted_rx) = oneshot::channel();
        let (replacement_deleted_tx, replacement_deleted_rx) = oneshot::channel();
        let gateway_task = tokio::spawn(async move {
            let mut grants = 0_u8;
            let mut first_deleted_tx = Some(first_deleted_tx);
            let mut replacement_deleted_tx = Some(replacement_deleted_tx);
            loop {
                let (stream, request) = receive_upnp_request(&listener).await;
                if request.contains("#GetExternalIPAddress\"") {
                    respond_upnp(
                        stream,
                        "GetExternalIPAddressResponse",
                        "<NewExternalIPAddress>198.51.100.10</NewExternalIPAddress>",
                    )
                    .await;
                } else if request.contains("#AddPortMapping\"") {
                    assert!(
                        request
                            .contains(&format!("<NewExternalPort>{first_port}</NewExternalPort>"))
                    );
                    // A transient connection failure does not remove the
                    // already confirmed first lease. The client falls back to
                    // requesting another port.
                    drop(stream);
                } else if request.contains("#AddAnyPortMapping\"") {
                    let port = if grants == 0 {
                        first_port
                    } else {
                        replacement_port
                    };
                    grants += 1;
                    respond_upnp(
                        stream,
                        "AddAnyPortMappingResponse",
                        &format!("<NewReservedPort>{port}</NewReservedPort>"),
                    )
                    .await;
                } else if request.contains("#DeletePortMapping\"") {
                    if request.contains(&format!("<NewExternalPort>{first_port}</NewExternalPort>"))
                    {
                        let _ = first_deleted_tx.take().unwrap().send(());
                    } else if request.contains(&format!(
                        "<NewExternalPort>{replacement_port}</NewExternalPort>"
                    )) {
                        let _ = replacement_deleted_tx.take().unwrap().send(());
                    } else {
                        panic!("unexpected UPnP deletion request: {request}");
                    }
                    respond_upnp(stream, "DeletePortMappingResponse", "").await;
                    if first_deleted_tx.is_none() && replacement_deleted_tx.is_none() {
                        break;
                    }
                } else {
                    panic!("unexpected UPnP request: {request}");
                }
            }
            assert_eq!(grants, 2);
        });

        let first = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway.clone()),
            None,
        )
        .await
        .unwrap();
        let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let (mut service, external) =
            Service::new(Config::default(), service_rx, Default::default());
        service.local_port = Some(local_port);
        service.current_mapping.update(Some(first));

        let replacement = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway),
            Some(first_port.try_into().unwrap()),
        )
        .await
        .unwrap();
        service.on_mapping_result(Ok(Ok(replacement))).await;
        tokio::time::timeout(Duration::from_secs(1), first_deleted_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(external.borrow().unwrap().port(), replacement_port);

        let (result_tx, result_rx) = oneshot::channel();
        service.handle_msg(Message::Deactivate { result_tx }).await;
        result_rx.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(1), replacement_deleted_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(external.borrow().is_none());
        tokio::time::timeout(Duration::from_secs(1), gateway_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn upnp_same_port_renewal_keeps_the_renewed_lease_active() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gateway = upnp_test_gateway(listener.local_addr().unwrap());
        let local_ip = Ipv4Addr::LOCALHOST;
        let local_port = NonZeroU16::new(39_501).unwrap();
        let external_port = 45_102_u16;
        let (deleted_tx, mut deleted_rx) = oneshot::channel();
        let gateway_task = tokio::spawn(async move {
            let mut first_granted = false;
            let mut renewed = false;
            let mut deleted_tx = Some(deleted_tx);
            loop {
                let (stream, request) = receive_upnp_request(&listener).await;
                if request.contains("#GetExternalIPAddress\"") {
                    respond_upnp(
                        stream,
                        "GetExternalIPAddressResponse",
                        "<NewExternalIPAddress>198.51.100.11</NewExternalIPAddress>",
                    )
                    .await;
                } else if request.contains("#AddAnyPortMapping\"") {
                    assert!(!first_granted);
                    first_granted = true;
                    respond_upnp(
                        stream,
                        "AddAnyPortMappingResponse",
                        &format!("<NewReservedPort>{external_port}</NewReservedPort>"),
                    )
                    .await;
                } else if request.contains("#AddPortMapping\"") {
                    assert!(first_granted);
                    assert!(!renewed);
                    assert!(request.contains(&format!(
                        "<NewExternalPort>{external_port}</NewExternalPort>"
                    )));
                    renewed = true;
                    respond_upnp(stream, "AddPortMappingResponse", "").await;
                } else if request.contains("#DeletePortMapping\"") {
                    assert!(renewed);
                    assert!(request.contains(&format!(
                        "<NewExternalPort>{external_port}</NewExternalPort>"
                    )));
                    let _ = deleted_tx.take().unwrap().send(());
                    respond_upnp(stream, "DeletePortMappingResponse", "").await;
                    break;
                } else {
                    panic!("unexpected UPnP request: {request}");
                }
            }
        });

        let first = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway.clone()),
            None,
        )
        .await
        .unwrap();
        let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let (mut service, external) =
            Service::new(Config::default(), service_rx, Default::default());
        service.local_port = Some(local_port);
        service.current_mapping.update(Some(first));

        let renewed = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway),
            Some(external_port.try_into().unwrap()),
        )
        .await
        .unwrap();
        service.on_mapping_result(Ok(Ok(renewed))).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut deleted_rx)
                .await
                .is_err(),
            "same-port renewal deleted the active lease"
        );
        assert_eq!(external.borrow().unwrap().port(), external_port);

        let (result_tx, result_rx) = oneshot::channel();
        service.handle_msg(Message::Deactivate { result_tx }).await;
        result_rx.await.unwrap().unwrap();
        deleted_rx.await.unwrap();
        assert!(external.borrow().is_none());
        tokio::time::timeout(Duration::from_secs(1), gateway_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn upnp_superseded_release_failure_is_reported_after_active_cleanup() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gateway = upnp_test_gateway(listener.local_addr().unwrap());
        let local_ip = Ipv4Addr::LOCALHOST;
        let local_port = NonZeroU16::new(39_502).unwrap();
        let first_port = 45_103_u16;
        let replacement_port = 45_104_u16;
        let (replacement_deleted_tx, replacement_deleted_rx) = oneshot::channel();
        let gateway_task = tokio::spawn(async move {
            let mut grants = 0_u8;
            let mut replacement_deleted_tx = Some(replacement_deleted_tx);
            loop {
                let (stream, request) = receive_upnp_request(&listener).await;
                if request.contains("#GetExternalIPAddress\"") {
                    respond_upnp(
                        stream,
                        "GetExternalIPAddressResponse",
                        "<NewExternalIPAddress>198.51.100.12</NewExternalIPAddress>",
                    )
                    .await;
                } else if request.contains("#AddPortMapping\"") {
                    drop(stream);
                } else if request.contains("#AddAnyPortMapping\"") {
                    let port = if grants == 0 {
                        first_port
                    } else {
                        replacement_port
                    };
                    grants += 1;
                    respond_upnp(
                        stream,
                        "AddAnyPortMappingResponse",
                        &format!("<NewReservedPort>{port}</NewReservedPort>"),
                    )
                    .await;
                } else if request.contains("#DeletePortMapping\"")
                    && request.contains(&format!("<NewExternalPort>{first_port}</NewExternalPort>"))
                {
                    // Losing the response makes cleanup incomplete. The
                    // service must remember that failure while continuing to
                    // own and release the replacement lease.
                    drop(stream);
                } else if request.contains("#DeletePortMapping\"")
                    && request.contains(&format!(
                        "<NewExternalPort>{replacement_port}</NewExternalPort>"
                    ))
                {
                    let _ = replacement_deleted_tx.take().unwrap().send(());
                    respond_upnp(stream, "DeletePortMappingResponse", "").await;
                    break;
                } else {
                    panic!("unexpected UPnP request: {request}");
                }
            }
        });

        let first = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway.clone()),
            None,
        )
        .await
        .unwrap();
        let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let (mut service, external) =
            Service::new(Config::default(), service_rx, Default::default());
        service.local_port = Some(local_port);
        service.current_mapping.update(Some(first));
        let replacement = mapping::Mapping::new_upnp(
            Protocol::Udp,
            local_ip,
            local_port,
            Some(gateway),
            Some(first_port.try_into().unwrap()),
        )
        .await
        .unwrap();
        service.on_mapping_result(Ok(Ok(replacement))).await;

        let (result_tx, result_rx) = oneshot::channel();
        service.handle_msg(Message::Deactivate { result_tx }).await;
        let error = result_rx.await.unwrap().unwrap_err();
        assert!(error.contains("UPnP mapping failed"));
        tokio::time::timeout(Duration::from_secs(1), replacement_deleted_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(external.borrow().is_none());
        tokio::time::timeout(Duration::from_secs(1), gateway_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn runtime_shutdown_cannot_observe_success_while_a_granted_mapping_is_owned() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (cleanup_task, cleanup_timed_out) = runtime.block_on(async {
            let gateway = Ipv4Addr::new(127, 0, 0, 5);
            let local_ip = Ipv4Addr::new(127, 0, 0, 6);
            let local_port = NonZeroU16::new(39_453).unwrap();
            let external_port = 45_002_u16;
            let gateway_socket = tokio::net::UdpSocket::bind((gateway, 5351)).await.unwrap();
            let gateway_task = tokio::spawn(async move {
                let mut packet = [0_u8; 64];
                let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..read], &[0, 0]);
                let mut public_response = vec![0, 128, 0, 0];
                public_response.extend_from_slice(&0_u32.to_be_bytes());
                public_response.extend_from_slice(&[198, 51, 100, 9]);
                gateway_socket
                    .send_to(&public_response, peer)
                    .await
                    .unwrap();

                let (read, peer) = gateway_socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(read, 12);
                assert_eq!(&packet[..4], &[0, 1, 0, 0]);
                assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), local_port.get());
                assert_ne!(u32::from_be_bytes(packet[8..12].try_into().unwrap()), 0);
                let mut mapping_response = vec![0, 129, 0, 0];
                mapping_response.extend_from_slice(&0_u32.to_be_bytes());
                mapping_response.extend_from_slice(&local_port.get().to_be_bytes());
                mapping_response.extend_from_slice(&external_port.to_be_bytes());
                mapping_response.extend_from_slice(&7_200_u32.to_be_bytes());
                gateway_socket
                    .send_to(&mapping_response, peer)
                    .await
                    .unwrap();
            });
            let mapping =
                mapping::Mapping::new_nat_pmp(Protocol::Udp, local_ip, local_port, gateway, None)
                    .await
                    .unwrap();
            gateway_task.await.unwrap();

            let (_service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
            let (mut service, _external) =
                Service::new(Config::default(), service_rx, Default::default());
            service.local_port = Some(local_port);
            service.mapping_task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
                let _mapping = mapping;
                std::future::pending::<Result<mapping::Mapping, mapping::Error>>().await
            })));

            // Model the daemon's bounded outer wait. A grant whose result is
            // still owned at the deadline must remain incomplete, rather than
            // being acknowledged and left in a detached task that runtime
            // teardown immediately cancels.
            tokio::time::pause();
            let mut cleanup_task =
                tokio::spawn(async move { service.update_local_port(None).await });
            let cleanup_timed_out = tokio::time::timeout(Duration::from_secs(6), &mut cleanup_task)
                .await
                .is_err();
            (cleanup_task, cleanup_timed_out)
        });

        assert!(cleanup_timed_out, "incomplete cleanup was acknowledged");
        assert!(!cleanup_task.is_finished());
        drop(runtime);
        assert!(cleanup_task.is_finished());
    }
}
