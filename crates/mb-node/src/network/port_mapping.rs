use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use anyhow::{Context, Result, bail};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;

use super::P2pClient;

/// Validate that automatic gateway mapping has one unambiguous IPv4 QUIC UDP
/// listener to expose. A zero configured port is allowed because Swarm replaces
/// it with the allocated port before [`run_port_mapping`] starts.
pub fn validate_port_mapping_listeners(addresses: &[Multiaddr]) -> Result<()> {
    let candidates = addresses
        .iter()
        .filter(|address| ipv4_quic_listener(address).is_some())
        .count();
    if candidates != 1 {
        bail!("port mapping requires exactly one non-loopback IPv4 UDP/QUIC listen address");
    }
    Ok(())
}

/// Maintain a real PCP, NAT-PMP, or UPnP mapping for the active QUIC listener
/// and feed every resulting external-address transition into libp2p.
pub async fn run_port_mapping(p2p: P2pClient) -> Result<()> {
    let status = p2p.status().await?;
    let mut ports = status
        .listen_addresses
        .iter()
        .filter_map(|value| value.parse::<Multiaddr>().ok())
        .filter_map(|address| ipv4_quic_listener(&address).map(|(_, port)| port));
    let local_port = ports
        .next()
        .and_then(NonZeroU16::new)
        .context("active IPv4 QUIC listener has no allocated UDP port")?;
    if ports.next().is_some() {
        bail!("active port-mapping listener is ambiguous");
    }

    loop {
        let client = portmapper::Client::new(portmapper::Config {
            enable_upnp: true,
            enable_pcp: true,
            enable_nat_pmp: true,
            protocol: portmapper::Protocol::Udp,
        });
        let mut external = client.watch_external_address();
        client.update_local_port(local_port);
        tracing::info!(
            port = local_port.get(),
            "requested automatic gateway port mapping"
        );

        let mut installed = None;
        loop {
            let current = *external.borrow_and_update();
            if current != installed {
                let address = current.map(|socket| {
                    Multiaddr::empty()
                        .with(Protocol::Ip4(*socket.ip()))
                        .with(Protocol::Udp(socket.port()))
                        .with(Protocol::QuicV1)
                });
                p2p.set_mapped_external_address(address).await?;
                installed = current;
                match current {
                    Some(socket) => tracing::info!(%socket, "automatic gateway mapping is active"),
                    None => tracing::warn!("automatic gateway mapping is no longer active"),
                }
            }
            if external.changed().await.is_err() {
                break;
            }
        }
        p2p.set_mapped_external_address(None).await?;
        tracing::warn!("port-mapping service stopped; retrying");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn ipv4_quic_listener(address: &Multiaddr) -> Option<(Ipv4Addr, u16)> {
    let mut protocols = address.iter();
    let Protocol::Ip4(ip) = protocols.next()? else {
        return None;
    };
    if ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return None;
    }
    let Protocol::Udp(port) = protocols.next()? else {
        return None;
    };
    if !matches!(protocols.next(), Some(Protocol::QuicV1)) || protocols.next().is_some() {
        return None;
    }
    Some((ip, port))
}

pub(super) fn valid_mapped_external_address(address: &Multiaddr) -> bool {
    ipv4_quic_listener(address).is_some_and(|(ip, port)| !ip.is_unspecified() && port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_mapping_listener_must_be_one_unambiguous_ipv4_quic_socket() {
        let wildcard: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
        validate_port_mapping_listeners(std::slice::from_ref(&wildcard)).unwrap();

        let ipv6: Multiaddr = "/ip6/::/udp/44000/quic-v1".parse().unwrap();
        validate_port_mapping_listeners(&[wildcard.clone(), ipv6]).unwrap();

        let second: Multiaddr = "/ip4/192.0.2.4/udp/44001/quic-v1".parse().unwrap();
        assert!(validate_port_mapping_listeners(&[wildcard, second]).is_err());
        assert!(
            validate_port_mapping_listeners(&["/ip4/127.0.0.1/udp/44000/quic-v1".parse().unwrap()])
                .is_err()
        );
        assert!(validate_port_mapping_listeners(&[]).is_err());
    }
}
