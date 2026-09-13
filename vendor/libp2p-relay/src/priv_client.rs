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

//! [`NetworkBehaviour`] to act as a circuit relay v2 **client**.

pub(crate) mod handler;
pub(crate) mod transport;

use std::{
    collections::{hash_map, HashMap, VecDeque},
    convert::Infallible,
    io::{Error, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use either::Either;
use futures::{
    channel::mpsc::Receiver,
    future::{BoxFuture, FutureExt},
    io::{AsyncRead, AsyncWrite},
    ready,
    stream::StreamExt,
};
use libp2p_core::{multiaddr::Protocol, transport::PortUse, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
    dial_opts::DialOpts,
    dummy, ConnectionDenied, ConnectionHandler, ConnectionId, DialFailure, NetworkBehaviour,
    NotifyHandler, Stream, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use transport::Transport;

use crate::{
    multiaddr_ext::MultiaddrExt,
    priv_client::handler::Handler,
    protocol::{self, inbound_stop},
};

/// The events produced by the client `Behaviour`.
#[derive(Debug)]
pub enum Event {
    /// An outbound reservation has been accepted.
    ReservationReqAccepted {
        relay_peer_id: PeerId,
        /// The connection that owns the reservation.
        connection_id: ConnectionId,
        /// Indicates whether the request replaces an existing reservation.
        renewal: bool,
        limit: Option<protocol::Limit>,
    },
    /// The reservation ended while the relay connection remained open.
    ReservationClosed {
        relay_peer_id: PeerId,
        connection_id: ConnectionId,
    },
    OutboundCircuitEstablished {
        relay_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
    /// An inbound circuit has been established.
    InboundCircuitEstablished {
        src_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ReservationStatus {
    Pending,
    Confirmed,
}

/// Identifies one reservation or renewal attempt on a relay connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ReservationId(u64);

/// [`NetworkBehaviour`] implementation of the relay client
/// functionality of the circuit relay v2 protocol.
pub struct Behaviour {
    local_peer_id: PeerId,

    from_transport: Receiver<transport::TransportToBehaviourMsg>,
    /// Set of directly connected peers, i.e. not connected via a relayed
    /// connection.
    directly_connected_peers: HashMap<PeerId, Vec<ConnectionId>>,

    /// Stores the address of each pending or confirmed reservation request.
    ///
    /// The outer key is the [`ConnectionId`] to a relay server. The inner key
    /// separates concurrent requests so one terminal event cannot consume
    /// another request's `/p2p-circuit` address.
    reservation_addresses:
        HashMap<ConnectionId, HashMap<ReservationId, (Multiaddr, ReservationStatus)>>,

    next_reservation_id: u64,

    /// Queue of actions to return when polled.
    queued_actions: VecDeque<ToSwarm<Event, Either<handler::In, Infallible>>>,

    pending_handler_commands: HashMap<ConnectionId, handler::In>,
}

/// Create a new client relay [`Behaviour`] with it's corresponding [`Transport`].
pub fn new(local_peer_id: PeerId) -> (Transport, Behaviour) {
    let (transport, from_transport) = Transport::new();
    let behaviour = Behaviour {
        local_peer_id,
        from_transport,
        directly_connected_peers: Default::default(),
        reservation_addresses: Default::default(),
        next_reservation_id: 0,
        queued_actions: Default::default(),
        pending_handler_commands: Default::default(),
    };
    (transport, behaviour)
}

impl Behaviour {
    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            endpoint,
            ..
        }: ConnectionClosed,
    ) {
        if !endpoint.is_relayed() {
            match self.directly_connected_peers.entry(peer_id) {
                hash_map::Entry::Occupied(mut connections) => {
                    let position = connections
                        .get()
                        .iter()
                        .position(|c| c == &connection_id)
                        .expect("Connection to be known.");
                    connections.get_mut().remove(position);

                    if connections.get().is_empty() {
                        connections.remove();
                    }
                }
                hash_map::Entry::Vacant(_) => {
                    unreachable!("`on_connection_closed` for unconnected peer.")
                }
            };
            if let Some(reservations) = self.reservation_addresses.remove(&connection_id) {
                for (addr, status) in reservations.into_values() {
                    if status == ReservationStatus::Confirmed {
                        self.queued_actions
                            .push_back(ToSwarm::ExternalAddrExpired(addr));
                    }
                }
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let pending_handler_command = self.pending_handler_commands.remove(&connection_id);

        if local_addr.is_relayed() {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let mut handler = Handler::new(self.local_peer_id, peer, remote_addr.clone());

        if let Some(event) = pending_handler_command {
            handler.on_behaviour_event(event)
        }

        Ok(Either::Left(handler))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let pending_handler_command = self.pending_handler_commands.remove(&connection_id);

        if addr.is_relayed() {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }

        let mut handler = Handler::new(self.local_peer_id, peer, addr.clone());

        if let Some(event) = pending_handler_command {
            handler.on_behaviour_event(event)
        }

        Ok(Either::Left(handler))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            }) if !endpoint.is_relayed() => {
                self.directly_connected_peers
                    .entry(peer_id)
                    .or_default()
                    .push(connection_id);
            }
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::DialFailure(DialFailure { connection_id, .. }) => {
                self.reservation_addresses.remove(&connection_id);
                self.pending_handler_commands.remove(&connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        event_source: PeerId,
        connection: ConnectionId,
        handler_event: THandlerOutEvent<Self>,
    ) {
        let handler_event = match handler_event {
            Either::Left(e) => e,
            Either::Right(v) => libp2p_core::util::unreachable(v),
        };

        let event = match handler_event {
            handler::Event::ReservationReqAccepted {
                reservation_id,
                renewal,
                limit,
            } => {
                let reservations = self
                    .reservation_addresses
                    .get_mut(&connection)
                    .expect("relay connection has reservation requests");
                let pending = reservations
                    .get(&reservation_id)
                    .expect("relay reservation request exists")
                    .1
                    == ReservationStatus::Pending;

                if pending {
                    let superseded = reservations
                        .iter()
                        .filter_map(|(candidate, (_, status))| {
                            (*candidate != reservation_id
                                && *status == ReservationStatus::Confirmed)
                                .then_some(*candidate)
                        })
                        .collect::<Vec<_>>();
                    for superseded in superseded {
                        let (addr, _) = reservations
                            .remove(&superseded)
                            .expect("superseded relay reservation exists");
                        self.queued_actions
                            .push_back(ToSwarm::ExternalAddrExpired(addr));
                    }
                    let (addr, status) = reservations
                        .get_mut(&reservation_id)
                        .expect("accepted relay reservation request exists");
                    *status = ReservationStatus::Confirmed;
                    self.queued_actions
                        .push_back(ToSwarm::ExternalAddrConfirmed(addr.clone()));
                }

                Some(Event::ReservationReqAccepted {
                    relay_peer_id: event_source,
                    connection_id: connection,
                    renewal,
                    limit,
                })
            }
            handler::Event::ReservationReqFailed {
                reservation_id,
                reservation_closed,
            } => {
                let removed = self
                    .reservation_addresses
                    .get_mut(&connection)
                    .and_then(|reservations| reservations.remove(&reservation_id));
                if let Some((addr, ReservationStatus::Confirmed)) = removed {
                    self.queued_actions
                        .push_back(ToSwarm::ExternalAddrExpired(addr));
                }
                reservation_closed.then_some(Event::ReservationClosed {
                    relay_peer_id: event_source,
                    connection_id: connection,
                })
            }
            handler::Event::ReservationClosed { reservation_id } => {
                let removed = self
                    .reservation_addresses
                    .get_mut(&connection)
                    .and_then(|reservations| reservations.remove(&reservation_id));
                if let Some((addr, ReservationStatus::Confirmed)) = removed {
                    self.queued_actions
                        .push_back(ToSwarm::ExternalAddrExpired(addr));
                }
                Some(Event::ReservationClosed {
                    relay_peer_id: event_source,
                    connection_id: connection,
                })
            }
            handler::Event::OutboundCircuitEstablished { limit } => {
                Some(Event::OutboundCircuitEstablished {
                    relay_peer_id: event_source,
                    limit,
                })
            }
            handler::Event::InboundCircuitEstablished { src_peer_id, limit } => {
                Some(Event::InboundCircuitEstablished { src_peer_id, limit })
            }
        };

        if self
            .reservation_addresses
            .get(&connection)
            .is_some_and(HashMap::is_empty)
        {
            self.reservation_addresses.remove(&connection);
        }
        if let Some(event) = event {
            self.queued_actions.push_back(ToSwarm::GenerateEvent(event));
        }
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(action) = self.queued_actions.pop_front() {
            return Poll::Ready(action);
        }

        let action = match ready!(self.from_transport.poll_next_unpin(cx)) {
            Some(transport::TransportToBehaviourMsg::ListenReq {
                relay_peer_id,
                relay_addr,
                to_listener,
            }) => {
                match self
                    .directly_connected_peers
                    .get(&relay_peer_id)
                    .and_then(|cs| cs.first())
                {
                    Some(connection_id) => {
                        let reservation_id = ReservationId(self.next_reservation_id);
                        self.next_reservation_id = self.next_reservation_id.wrapping_add(1);
                        self.reservation_addresses
                            .entry(*connection_id)
                            .or_default()
                            .insert(
                                reservation_id,
                                (
                                    relay_addr
                                        .with(Protocol::P2p(relay_peer_id))
                                        .with(Protocol::P2pCircuit)
                                        .with(Protocol::P2p(self.local_peer_id)),
                                    ReservationStatus::Pending,
                                ),
                            );

                        ToSwarm::NotifyHandler {
                            peer_id: relay_peer_id,
                            handler: NotifyHandler::One(*connection_id),
                            event: Either::Left(handler::In::Reserve {
                                reservation_id,
                                to_listener,
                            }),
                        }
                    }
                    None => {
                        let opts = DialOpts::peer_id(relay_peer_id)
                            .addresses(vec![relay_addr.clone()])
                            .extend_addresses_through_behaviour()
                            .build();
                        let relayed_connection_id = opts.connection_id();

                        let reservation_id = ReservationId(self.next_reservation_id);
                        self.next_reservation_id = self.next_reservation_id.wrapping_add(1);
                        self.reservation_addresses
                            .entry(relayed_connection_id)
                            .or_default()
                            .insert(
                                reservation_id,
                                (
                                    relay_addr
                                        .with(Protocol::P2p(relay_peer_id))
                                        .with(Protocol::P2pCircuit)
                                        .with(Protocol::P2p(self.local_peer_id)),
                                    ReservationStatus::Pending,
                                ),
                            );

                        self.pending_handler_commands.insert(
                            relayed_connection_id,
                            handler::In::Reserve {
                                reservation_id,
                                to_listener,
                            },
                        );
                        ToSwarm::Dial { opts }
                    }
                }
            }
            Some(transport::TransportToBehaviourMsg::DialReq {
                relay_addr,
                relay_peer_id,
                dst_peer_id,
                send_back,
                ..
            }) => {
                match self
                    .directly_connected_peers
                    .get(&relay_peer_id)
                    .and_then(|cs| cs.first())
                {
                    Some(connection_id) => ToSwarm::NotifyHandler {
                        peer_id: relay_peer_id,
                        handler: NotifyHandler::One(*connection_id),
                        event: Either::Left(handler::In::EstablishCircuit {
                            to_dial: send_back,
                            dst_peer_id,
                        }),
                    },
                    None => {
                        let opts = DialOpts::peer_id(relay_peer_id)
                            .addresses(vec![relay_addr])
                            .extend_addresses_through_behaviour()
                            .build();
                        let connection_id = opts.connection_id();

                        self.pending_handler_commands.insert(
                            connection_id,
                            handler::In::EstablishCircuit {
                                to_dial: send_back,
                                dst_peer_id,
                            },
                        );

                        ToSwarm::Dial { opts }
                    }
                }
            }
            None => unreachable!(
                "`relay::Behaviour` polled after channel from \
                     `Transport` has been closed. Unreachable under \
                     the assumption that the `client::Behaviour` is never polled after \
                     `client::Transport` is dropped.",
            ),
        };

        Poll::Ready(action)
    }
}

/// Represents a connection to another peer via a relay.
///
/// Internally, this uses a stream to the relay.
pub struct Connection {
    pub(crate) state: ConnectionState,
}

pub(crate) enum ConnectionState {
    InboundAccepting {
        accept: BoxFuture<'static, Result<ConnectionState, Error>>,
    },
    Operational {
        read_buffer: Bytes,
        substream: Stream,
    },
}

impl Unpin for ConnectionState {}

impl ConnectionState {
    pub(crate) fn new_inbound(circuit: inbound_stop::Circuit) -> Self {
        ConnectionState::InboundAccepting {
            accept: async {
                let (substream, read_buffer) = circuit.accept().await.map_err(Error::other)?;
                Ok(ConnectionState::Operational {
                    read_buffer,
                    substream,
                })
            }
            .boxed(),
        }
    }

    pub(crate) fn new_outbound(substream: Stream, read_buffer: Bytes) -> Self {
        ConnectionState::Operational {
            substream,
            read_buffer,
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    *self = Connection {
                        state: ready!(accept.poll_unpin(cx))?,
                    };
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_write(cx, buf);
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    *self = Connection {
                        state: ready!(accept.poll_unpin(cx))?,
                    };
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_flush(cx);
                }
            }
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    *self = Connection {
                        state: ready!(accept.poll_unpin(cx))?,
                    };
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_close(cx);
                }
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        bufs: &[IoSlice],
    ) -> Poll<Result<usize, Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    *self = Connection {
                        state: ready!(accept.poll_unpin(cx))?,
                    };
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_write_vectored(cx, bufs);
                }
            }
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    *self = Connection {
                        state: ready!(accept.poll_unpin(cx))?,
                    };
                }
                ConnectionState::Operational {
                    read_buffer,
                    substream,
                    ..
                } => {
                    if !read_buffer.is_empty() {
                        let n = std::cmp::min(read_buffer.len(), buf.len());
                        let data = read_buffer.split_to(n);
                        buf[0..n].copy_from_slice(&data[..]);
                        return Poll::Ready(Ok(n));
                    }

                    return Pin::new(substream).poll_read(cx, buf);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_reservation_request_does_not_remove_a_later_request() {
        let local_peer_id = PeerId::random();
        let relay_peer_id = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        let first = ReservationId(1);
        let second = ReservationId(2);
        let first_addr = Multiaddr::empty().with(Protocol::Memory(1));
        let second_addr = Multiaddr::empty().with(Protocol::Memory(2));
        let (_, mut behaviour) = new(local_peer_id);
        behaviour.reservation_addresses.insert(
            connection,
            HashMap::from([
                (first, (first_addr, ReservationStatus::Pending)),
                (second, (second_addr.clone(), ReservationStatus::Pending)),
            ]),
        );

        behaviour.on_connection_handler_event(
            relay_peer_id,
            connection,
            Either::Left(handler::Event::ReservationReqFailed {
                reservation_id: first,
                reservation_closed: false,
            }),
        );
        assert!(
            behaviour.reservation_addresses[&connection].contains_key(&second),
            "an older failure removed the later request"
        );

        behaviour.on_connection_handler_event(
            relay_peer_id,
            connection,
            Either::Left(handler::Event::ReservationReqAccepted {
                reservation_id: second,
                renewal: false,
                limit: None,
            }),
        );
        assert_eq!(
            behaviour.reservation_addresses[&connection][&second],
            (second_addr, ReservationStatus::Confirmed)
        );
    }
}
