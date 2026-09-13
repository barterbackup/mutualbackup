// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt, io,
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    channel::{mpsc, mpsc::Sender, oneshot},
    future::FutureExt,
};
use futures_timer::Delay;
use libp2p_core::{multiaddr::Protocol, upgrade::ReadyUpgrade, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    handler::{ConnectionEvent, FullyNegotiatedInbound},
    ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, StreamUpgradeError,
    SubstreamProtocol,
};

use crate::{
    client::Connection,
    priv_client,
    priv_client::{transport, transport::ToListenerMsg, ReservationId},
    proto,
    protocol::{self, inbound_stop, outbound_hop},
    HOP_PROTOCOL_NAME, STOP_PROTOCOL_NAME,
};

/// The maximum number of circuits being denied concurrently.
///
/// Circuits to be denied exceeding the limit are dropped.
const MAX_NUMBER_DENYING_CIRCUIT: usize = 8;
const DENYING_CIRCUIT_TIMEOUT: Duration = Duration::from_secs(60);

const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 10;
const STREAM_TIMEOUT: Duration = Duration::from_secs(60);

pub enum In {
    Reserve {
        reservation_id: ReservationId,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
    },
    EstablishCircuit {
        dst_peer_id: PeerId,
        to_dial: oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>,
    },
}

impl fmt::Debug for In {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            In::Reserve {
                reservation_id,
                to_listener: _,
            } => f
                .debug_struct("In::Reserve")
                .field("reservation_id", reservation_id)
                .finish(),
            In::EstablishCircuit {
                dst_peer_id,
                to_dial: _,
            } => f
                .debug_struct("In::EstablishCircuit")
                .field("dst_peer_id", dst_peer_id)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    ReservationReqAccepted {
        reservation_id: ReservationId,
        /// Indicates whether the request replaces an existing reservation.
        renewal: bool,
        limit: Option<protocol::Limit>,
    },
    /// The reservation ended while the relay connection remained open.
    ReservationReqFailed {
        reservation_id: ReservationId,
        reservation_closed: bool,
    },
    ReservationClosed {
        reservation_id: ReservationId,
    },
    /// An outbound circuit has been established.
    OutboundCircuitEstablished {
        limit: Option<protocol::Limit>,
    },
    /// An inbound circuit has been established.
    InboundCircuitEstablished {
        src_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
}

pub struct Handler {
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    remote_addr: Multiaddr,

    /// Queue of events to return when polled.
    queued_events: VecDeque<
        ConnectionHandlerEvent<
            <Handler as ConnectionHandler>::OutboundProtocol,
            (),
            <Handler as ConnectionHandler>::ToBehaviour,
        >,
    >,

    pending_streams: VecDeque<oneshot::Sender<Result<Stream, StreamUpgradeError<Infallible>>>>,

    inflight_reserve_requests: futures_bounded::FuturesTupleSet<
        Result<outbound_hop::Reservation, outbound_hop::ReserveError>,
        PendingReservationRequest,
    >,

    inflight_outbound_connect_requests: futures_bounded::FuturesTupleSet<
        Result<outbound_hop::Circuit, outbound_hop::ConnectError>,
        oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>,
    >,

    inflight_inbound_circuit_requests:
        futures_bounded::FuturesSet<Result<inbound_stop::Circuit, inbound_stop::Error>>,

    inflight_outbound_circuit_deny_requests:
        futures_bounded::FuturesSet<Result<(), inbound_stop::Error>>,

    reservation: Reservation,
    pending_reservation_requests: VecDeque<PendingReservationRequest>,
}

struct PendingReservationRequest {
    reservation_id: ReservationId,
    to_listener: Sender<ToListenerMsg>,
}

impl Handler {
    pub fn new(local_peer_id: PeerId, remote_peer_id: PeerId, remote_addr: Multiaddr) -> Self {
        Self {
            local_peer_id,
            remote_peer_id,
            remote_addr,
            queued_events: Default::default(),
            pending_streams: Default::default(),
            inflight_reserve_requests: futures_bounded::FuturesTupleSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_inbound_circuit_requests: futures_bounded::FuturesSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_outbound_connect_requests: futures_bounded::FuturesTupleSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_outbound_circuit_deny_requests: futures_bounded::FuturesSet::new(
                DENYING_CIRCUIT_TIMEOUT,
                MAX_NUMBER_DENYING_CIRCUIT,
            ),
            reservation: Reservation::None,
            pending_reservation_requests: VecDeque::new(),
        }
    }

    fn insert_to_deny_futs(&mut self, circuit: inbound_stop::Circuit) {
        let src_peer_id = circuit.src_peer_id();

        if self
            .inflight_outbound_circuit_deny_requests
            .try_push(circuit.deny(proto::Status::NO_RESERVATION))
            .is_err()
        {
            tracing::warn!(
                peer=%src_peer_id,
                "Dropping existing inbound circuit request to be denied from peer in favor of new one"
            )
        }
    }

    fn make_new_reservation(&mut self, request: PendingReservationRequest) {
        self.pending_reservation_requests.push_back(request);
        self.start_next_reservation_if_idle();
    }

    fn start_next_reservation_if_idle(&mut self) {
        if !self.inflight_reserve_requests.is_empty() {
            return;
        }
        let Some(request) = self.pending_reservation_requests.pop_front() else {
            return;
        };
        let (sender, receiver) = oneshot::channel();

        self.pending_streams.push_back(sender);
        self.queued_events
            .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(HOP_PROTOCOL_NAME), ()),
            });
        let result = self.inflight_reserve_requests.try_push(
            async move {
                let stream = receiver
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_reserve_error)?;

                let reservation = outbound_hop::make_reservation(stream).await?;

                Ok(reservation)
            },
            request,
        );

        if result.is_err() {
            tracing::warn!("Dropping in-flight reservation request because we are at capacity");
        }
    }

    fn establish_new_circuit(
        &mut self,
        to_dial: oneshot::Sender<Result<Connection, outbound_hop::ConnectError>>,
        dst_peer_id: PeerId,
    ) {
        let (sender, receiver) = oneshot::channel();

        self.pending_streams.push_back(sender);
        self.queued_events
            .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(HOP_PROTOCOL_NAME), ()),
            });
        let result = self.inflight_outbound_connect_requests.try_push(
            async move {
                let stream = receiver
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_connect_error)?;

                outbound_hop::open_circuit(stream, dst_peer_id).await
            },
            to_dial,
        );

        if result.is_err() {
            tracing::warn!("Dropping in-flight connect request because we are at capacity")
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = In;
    type ToBehaviour = Event;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(STOP_PROTOCOL_NAME), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            In::Reserve {
                reservation_id,
                to_listener,
            } => {
                self.make_new_reservation(PendingReservationRequest {
                    reservation_id,
                    to_listener,
                });
            }
            In::EstablishCircuit {
                to_dial,
                dst_peer_id,
            } => {
                self.establish_new_circuit(to_dial, dst_peer_id);
            }
        }
    }

    fn connection_keep_alive(&self) -> bool {
        self.reservation.is_some()
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Self::ToBehaviour>> {
        loop {
            self.start_next_reservation_if_idle();
            // Reservations
            match self.inflight_reserve_requests.poll_unpin(cx) {
                Poll::Ready((
                    Ok(Ok(outbound_hop::Reservation {
                        renewal_timeout,
                        addrs,
                        limit,
                    })),
                    request,
                )) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        self.reservation.accepted(
                            request.reservation_id,
                            renewal_timeout,
                            addrs,
                            request.to_listener,
                            self.local_peer_id,
                            limit,
                        ),
                    ));
                }
                Poll::Ready((Ok(Err(error)), mut request)) => {
                    if let Err(e) = request
                        .to_listener
                        .try_send(transport::ToListenerMsg::Reservation(Err(error)))
                    {
                        tracing::debug!("Unable to send error to listener: {}", e.into_send_error())
                    }
                    let reservation_closed = self.reservation.failed(request.reservation_id);
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::ReservationReqFailed {
                            reservation_id: request.reservation_id,
                            reservation_closed,
                        },
                    ));
                }
                Poll::Ready((Err(futures_bounded::Timeout { .. }), mut request)) => {
                    if let Err(e) =
                        request
                            .to_listener
                            .try_send(transport::ToListenerMsg::Reservation(Err(
                                outbound_hop::ReserveError::Io(io::ErrorKind::TimedOut.into()),
                            )))
                    {
                        tracing::debug!("Unable to send error to listener: {}", e.into_send_error())
                    }
                    let reservation_closed = self.reservation.failed(request.reservation_id);
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::ReservationReqFailed {
                            reservation_id: request.reservation_id,
                            reservation_closed,
                        },
                    ));
                }
                Poll::Pending => {}
            }

            // Circuits
            match self.inflight_outbound_connect_requests.poll_unpin(cx) {
                Poll::Ready((
                    Ok(Ok(outbound_hop::Circuit {
                        limit,
                        read_buffer,
                        stream,
                    })),
                    to_dialer,
                )) => {
                    if to_dialer
                        .send(Ok(priv_client::Connection {
                            state: priv_client::ConnectionState::new_outbound(stream, read_buffer),
                        }))
                        .is_err()
                    {
                        tracing::debug!(
                            "Dropping newly established circuit because the listener is gone"
                        );
                        continue;
                    }

                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::OutboundCircuitEstablished { limit },
                    ));
                }
                Poll::Ready((Ok(Err(error)), to_dialer)) => {
                    let _ = to_dialer.send(Err(error));
                    continue;
                }
                Poll::Ready((Err(futures_bounded::Timeout { .. }), to_dialer)) => {
                    if to_dialer
                        .send(Err(outbound_hop::ConnectError::Io(
                            io::ErrorKind::TimedOut.into(),
                        )))
                        .is_err()
                    {
                        tracing::debug!("Unable to send error to dialer")
                    }
                    continue;
                }
                Poll::Pending => {}
            }

            // Return queued events.
            if let Some(event) = self.queued_events.pop_front() {
                return Poll::Ready(event);
            }

            match self.inflight_inbound_circuit_requests.poll_unpin(cx) {
                Poll::Ready(Ok(Ok(circuit))) => match &mut self.reservation {
                    Reservation::Accepted { pending_msgs, .. }
                    | Reservation::Renewing { pending_msgs, .. } => {
                        let src_peer_id = circuit.src_peer_id();
                        let limit = circuit.limit();

                        let connection = super::ConnectionState::new_inbound(circuit);

                        pending_msgs.push_back(
                            transport::ToListenerMsg::IncomingRelayedConnection {
                                stream: super::Connection { state: connection },
                                src_peer_id,
                                relay_peer_id: self.remote_peer_id,
                                relay_addr: self.remote_addr.clone(),
                            },
                        );
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            Event::InboundCircuitEstablished { src_peer_id, limit },
                        ));
                    }
                    Reservation::None => {
                        self.insert_to_deny_futs(circuit);
                        continue;
                    }
                },
                Poll::Ready(Ok(Err(e))) => {
                    tracing::debug!("An inbound circuit request failed: {e}");
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    tracing::debug!("An inbound circuit request timed out: {e}");
                    continue;
                }
                Poll::Pending => {}
            }

            let allow_renewal = self.inflight_reserve_requests.is_empty()
                && self.pending_reservation_requests.is_empty();
            match self.reservation.poll(cx, allow_renewal) {
                Poll::Ready(ReservationPoll::Renew(request)) => {
                    self.make_new_reservation(request);
                    continue;
                }
                Poll::Ready(ReservationPoll::Closed(reservation_id)) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::ReservationClosed { reservation_id },
                    ));
                }
                Poll::Pending => {}
            }

            // Deny incoming circuit requests.
            match self.inflight_outbound_circuit_deny_requests.poll_unpin(cx) {
                Poll::Ready(Ok(Ok(()))) => continue,
                Poll::Ready(Ok(Err(error))) => {
                    tracing::debug!("Denying inbound circuit failed: {error}");
                    continue;
                }
                Poll::Ready(Err(futures_bounded::Timeout { .. })) => {
                    tracing::debug!("Denying inbound circuit timed out");
                    continue;
                }
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                if self
                    .inflight_inbound_circuit_requests
                    .try_push(inbound_stop::handle_open_circuit(stream))
                    .is_err()
                {
                    tracing::warn!("Dropping inbound stream because we are at capacity")
                }
            }
            ConnectionEvent::FullyNegotiatedOutbound(ev) => {
                if let Some(next) = self.pending_streams.pop_front() {
                    let _ = next.send(Ok(ev.protocol));
                }
            }
            ConnectionEvent::ListenUpgradeError(ev) => libp2p_core::util::unreachable(ev.error),
            ConnectionEvent::DialUpgradeError(ev) => {
                if let Some(next) = self.pending_streams.pop_front() {
                    let _ = next.send(Err(ev.error));
                }
            }
            _ => {}
        }
    }
}

enum Reservation {
    /// The Reservation is accepted by the relay.
    Accepted {
        reservation_id: ReservationId,
        renewal_timeout: Delay,
        /// Buffer of messages to be send to the transport listener.
        pending_msgs: VecDeque<transport::ToListenerMsg>,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
    },
    /// The reservation is being renewed with the relay.
    Renewing {
        reservation_id: ReservationId,
        /// Buffer of messages to be send to the transport listener.
        pending_msgs: VecDeque<transport::ToListenerMsg>,
    },
    None,
}

impl Reservation {
    fn accepted(
        &mut self,
        reservation_id: ReservationId,
        renewal_timeout: Delay,
        addrs: Vec<Multiaddr>,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
        local_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    ) -> Event {
        let (renewal, mut pending_msgs) = match std::mem::replace(self, Self::None) {
            Reservation::Accepted { pending_msgs, .. }
            | Reservation::Renewing { pending_msgs, .. } => (true, pending_msgs),
            Reservation::None => (false, VecDeque::new()),
        };

        pending_msgs.push_back(transport::ToListenerMsg::Reservation(Ok(
            transport::Reservation {
                addrs: addrs
                    .into_iter()
                    .map(|a| {
                        a.with(Protocol::P2pCircuit)
                            .with(Protocol::P2p(local_peer_id))
                    })
                    .collect(),
            },
        )));

        *self = Reservation::Accepted {
            reservation_id,
            renewal_timeout,
            pending_msgs,
            to_listener,
        };

        Event::ReservationReqAccepted {
            reservation_id,
            renewal,
            limit,
        }
    }

    fn is_some(&self) -> bool {
        matches!(self, Self::Accepted { .. } | Self::Renewing { .. })
    }

    /// Marks the current reservation as failed.
    fn failed(&mut self, reservation_id: ReservationId) -> bool {
        let closes_active = matches!(
            self,
            Reservation::Accepted {
                reservation_id: active,
                ..
            } | Reservation::Renewing {
                reservation_id: active,
                ..
            } if *active == reservation_id
        );
        if closes_active {
            *self = Reservation::None;
        }
        closes_active
    }

    fn forward_messages_to_transport_listener(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<ReservationId> {
        if let Reservation::Accepted {
            reservation_id,
            pending_msgs,
            to_listener,
            ..
        } = self
        {
            if !pending_msgs.is_empty() {
                match to_listener.poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        if let Err(e) = to_listener
                            .start_send(pending_msgs.pop_front().expect("Called !is_empty()."))
                        {
                            tracing::debug!("Failed to sent pending message to listener: {:?}", e);
                            let reservation_id = *reservation_id;
                            *self = Reservation::None;
                            return Some(reservation_id);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::debug!("Channel to listener failed: {:?}", e);
                        let reservation_id = *reservation_id;
                        *self = Reservation::None;
                        return Some(reservation_id);
                    }
                    Poll::Pending => {}
                }
            }
        }
        None
    }

    fn poll(&mut self, cx: &mut Context<'_>, allow_renewal: bool) -> Poll<ReservationPoll> {
        if let Some(reservation_id) = self.forward_messages_to_transport_listener(cx) {
            return Poll::Ready(ReservationPoll::Closed(reservation_id));
        }

        // Check renewal timeout if any.
        let (next_reservation, poll_val) = match std::mem::replace(self, Reservation::None) {
            Reservation::Accepted {
                reservation_id,
                mut renewal_timeout,
                pending_msgs,
                to_listener,
            } => match renewal_timeout.poll_unpin(cx) {
                Poll::Ready(()) if allow_renewal => (
                    Reservation::Renewing {
                        reservation_id,
                        pending_msgs,
                    },
                    Poll::Ready(ReservationPoll::Renew(PendingReservationRequest {
                        reservation_id,
                        to_listener,
                    })),
                ),
                _ => (
                    Reservation::Accepted {
                        reservation_id,
                        renewal_timeout,
                        pending_msgs,
                        to_listener,
                    },
                    Poll::Pending,
                ),
            },
            r => (r, Poll::Pending),
        };
        *self = next_reservation;

        poll_val
    }
}

enum ReservationPoll {
    Renew(PendingReservationRequest),
    Closed(ReservationId),
}

fn into_reserve_error(e: StreamUpgradeError<Infallible>) -> outbound_hop::ReserveError {
    match e {
        StreamUpgradeError::Timeout => {
            outbound_hop::ReserveError::Io(io::ErrorKind::TimedOut.into())
        }
        StreamUpgradeError::Apply(never) => libp2p_core::util::unreachable(never),
        StreamUpgradeError::NegotiationFailed => outbound_hop::ReserveError::Unsupported,
        StreamUpgradeError::Io(e) => outbound_hop::ReserveError::Io(e),
    }
}

fn into_connect_error(e: StreamUpgradeError<Infallible>) -> outbound_hop::ConnectError {
    match e {
        StreamUpgradeError::Timeout => {
            outbound_hop::ConnectError::Io(io::ErrorKind::TimedOut.into())
        }
        StreamUpgradeError::Apply(never) => libp2p_core::util::unreachable(never),
        StreamUpgradeError::NegotiationFailed => outbound_hop::ConnectError::Unsupported,
        StreamUpgradeError::Io(e) => outbound_hop::ConnectError::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_requests_are_serialized_per_connection() {
        let mut handler = Handler::new(PeerId::random(), PeerId::random(), Multiaddr::empty());
        let (first, _) = mpsc::channel(0);
        let (second, _) = mpsc::channel(0);

        handler.on_behaviour_event(In::Reserve {
            reservation_id: ReservationId(1),
            to_listener: first,
        });
        handler.on_behaviour_event(In::Reserve {
            reservation_id: ReservationId(2),
            to_listener: second,
        });

        assert_eq!(handler.inflight_reserve_requests.len(), 1);
        assert_eq!(handler.pending_reservation_requests.len(), 1);
    }
}
