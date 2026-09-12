use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU16;

use anyhow::{Context, Result, bail};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tokio::sync::watch;

use super::P2pClient;

const MAPPING_WITHDRAW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAPPING_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Validate that automatic gateway mapping has one unambiguous wildcard IPv4
/// QUIC UDP listener to expose. The mapper uses the default-route local address,
/// so a listener bound to another specific interface is not sufficient. A zero
/// configured port is allowed because Swarm replaces it before mapping starts.
pub fn validate_port_mapping_listeners(addresses: &[Multiaddr]) -> Result<()> {
    let candidates = addresses
        .iter()
        .filter_map(ipv4_quic_listener)
        .collect::<Vec<_>>();
    if candidates.len() != 1 || !candidates[0].0.is_unspecified() {
        bail!("port mapping requires exactly one wildcard IPv4 UDP/QUIC listen address");
    }
    Ok(())
}

/// Maintain a real PCP, NAT-PMP, or UPnP mapping for the active QUIC listener
/// and feed every resulting external-address transition into libp2p.
pub async fn run_port_mapping(p2p: P2pClient, mut shutdown: watch::Receiver<bool>) -> Result<()> {
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

    let client = portmapper::Client::new(portmapper::Config {
        enable_upnp: true,
        enable_pcp: true,
        enable_nat_pmp: true,
        protocol: portmapper::Protocol::Udp,
    });
    let mut external = client.watch_external_address();
    probe_gateway_mapping_protocols(&client).await;
    client.update_local_port(local_port);
    tracing::info!(
        port = local_port.get(),
        "requested automatic gateway port mapping"
    );

    let mut installed = None;
    let mut retry = tokio::time::interval_at(
        tokio::time::Instant::now() + MAPPING_RETRY_INTERVAL,
        MAPPING_RETRY_INTERVAL,
    );
    let outcome = loop {
        let current = *external.borrow_and_update();
        if current != installed {
            let address = current.map(|socket| {
                Multiaddr::empty()
                    .with(Protocol::Ip4(*socket.ip()))
                    .with(Protocol::Udp(socket.port()))
                    .with(Protocol::QuicV1)
            });
            if let Err(error) = p2p.set_mapped_external_address(address).await {
                break Err(error.context("publish automatic gateway mapping"));
            }
            installed = current;
            match current {
                Some(socket) => tracing::info!(%socket, "automatic gateway mapping is active"),
                None => tracing::warn!("automatic gateway mapping is no longer active"),
            }
        }
        tokio::select! {
            changed = external.changed() => {
                if changed.is_err() {
                    break Err(anyhow::anyhow!("port-mapping service stopped"));
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
            _ = retry.tick(), if installed.is_none() => {
                probe_gateway_mapping_protocols(&client).await;
                client.procure_mapping();
            }
        }
    };

    let cleanup = withdraw_gateway_mapping(&p2p, &client, &mut external).await;
    match (outcome, cleanup) {
        (Err(error), Err(cleanup_error)) => {
            tracing::warn!(%cleanup_error, "gateway mapping cleanup also failed");
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

async fn withdraw_gateway_mapping(
    p2p: &P2pClient,
    client: &portmapper::Client,
    external: &mut watch::Receiver<Option<SocketAddrV4>>,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + MAPPING_WITHDRAW_TIMEOUT;

    let release_result: Result<()> = async {
        // Attempt deactivation immediately. If its nonblocking enqueue met a
        // full queue, the first barrier drains that queue and a second
        // deactivation is then guaranteed a slot. The final barrier
        // acknowledges processing after the protocol-specific delete attempt.
        client.deactivate();
        let initial_barrier = tokio::time::timeout_at(deadline, client.probe())
            .await
            .context("timed out preparing the gateway mapping release")?
            .context("port-mapping service stopped before gateway release")?;
        if matches!(
            initial_barrier,
            Err(portmapper::ProbeError::ChannelFull { .. }
                | portmapper::ProbeError::ChannelClosed { .. })
        ) {
            bail!("port-mapping service did not accept the release preflight");
        }
        client.deactivate();
        let release_barrier = tokio::time::timeout_at(deadline, client.probe())
            .await
            .context("timed out waiting for the gateway mapping release")?
            .context("port-mapping service stopped during gateway release")?;
        if matches!(
            release_barrier,
            Err(portmapper::ProbeError::ChannelFull { .. }
                | portmapper::ProbeError::ChannelClosed { .. })
        ) {
            bail!("port-mapping service did not accept the release barrier");
        }
        while external.borrow().is_some() {
            tokio::time::timeout_at(deadline, external.changed())
                .await
                .context("timed out withdrawing automatic gateway mapping")?
                .context("port-mapping service stopped before withdrawal")?;
        }
        Ok(())
    }
    .await;
    let address_result = p2p.set_mapped_external_address(None).await;
    match (release_result, address_result) {
        (Err(error), Err(address_error)) => {
            tracing::warn!(%address_error, "withdrawing the libp2p mapped address also failed");
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => {
            tracing::info!("automatic gateway mapping withdrawn");
            Ok(())
        }
    }
}

async fn probe_gateway_mapping_protocols(client: &portmapper::Client) {
    match tokio::time::timeout(PROBE_TIMEOUT, client.probe()).await {
        Ok(Ok(Ok(available))) => tracing::debug!(?available, "gateway mapping probe completed"),
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "gateway mapping probe failed; using protocol fallback")
        }
        Ok(Err(_)) => {
            tracing::warn!("gateway mapping probe service stopped; using protocol fallback")
        }
        Err(_) => tracing::warn!("gateway mapping probe timed out; using protocol fallback"),
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

    async fn fixture_control(command: &str) {
        let address = std::env::var("MUTUALBACKUP_NAT_PMP_CONTROL").unwrap();
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket.connect(address).await.unwrap();
        socket.send(command.as_bytes()).await.unwrap();
        let mut reply = [0_u8; 16];
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv(&mut reply))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&reply[..received], b"ok");
    }

    async fn wait_for_mapping(client: &P2pClient, expected_port: Option<u16>) {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let status = client.status().await.unwrap();
                let observed = status
                    .port_mapping_external_address
                    .as_deref()
                    .and_then(|address| address.parse::<Multiaddr>().ok())
                    .and_then(|address| ipv4_quic_listener(&address));
                let advertised = status
                    .advertised_addresses
                    .iter()
                    .filter_map(|address| address.parse::<Multiaddr>().ok())
                    .filter_map(|address| ipv4_quic_listener(&address))
                    .filter(|(ip, _)| *ip == "198.51.100.7".parse::<Ipv4Addr>().unwrap())
                    .collect::<Vec<_>>();
                if observed == expected_port.map(|port| ("198.51.100.7".parse().unwrap(), port))
                    && advertised
                        == expected_port
                            .map(|port| vec![("198.51.100.7".parse().unwrap(), port)])
                            .unwrap_or_default()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("mapping did not converge to external port {expected_port:?}"));
    }

    #[test]
    fn port_mapping_listener_must_be_one_unambiguous_ipv4_quic_socket() {
        let wildcard: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
        validate_port_mapping_listeners(std::slice::from_ref(&wildcard)).unwrap();

        let ipv6: Multiaddr = "/ip6/::/udp/44000/quic-v1".parse().unwrap();
        validate_port_mapping_listeners(&[wildcard.clone(), ipv6]).unwrap();

        let second: Multiaddr = "/ip4/192.0.2.4/udp/44001/quic-v1".parse().unwrap();
        assert!(validate_port_mapping_listeners(&[wildcard, second.clone()]).is_err());
        assert!(validate_port_mapping_listeners(&[second]).is_err());
        assert!(
            validate_port_mapping_listeners(&["/ip4/127.0.0.1/udp/44000/quic-v1".parse().unwrap()])
                .is_err()
        );
        assert!(validate_port_mapping_listeners(&[]).is_err());
    }

    #[tokio::test]
    async fn real_nat_pmp_mapping_is_published_replaced_reacquired_and_withdrawn() {
        let Ok(events_path) = std::env::var("MUTUALBACKUP_NAT_PMP_EVENTS") else {
            return;
        };
        use super::super::{P2pConfig, TorMode, build_p2p};
        use crate::{Node, Seed};
        use std::sync::{Arc, Mutex};

        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([61; 32])).unwrap();
        let node_id = node.keys().node_id();
        let config = P2pConfig {
            listen_addresses: vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()],
            external_addresses: Vec::new(),
            bootstrap_addresses: Vec::new(),
            relay_reservation_addresses: Vec::new(),
            enable_dht_maintenance: false,
            enable_relay_server: false,
            enable_hole_punching: false,
            enable_port_mapping: true,
            public_endpoint: "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
            failure_domain: node_id.to_string(),
            configure_failure_domain: true,
            max_connections: 4,
            tor_mode: TorMode::DisableTor,
        };
        let (client, mut event_loop) = build_p2p(Arc::new(Mutex::new(node)), config).unwrap();
        let startup = event_loop.take_startup_receiver().unwrap();
        let p2p_task = tokio::spawn(event_loop.run());
        tokio::time::timeout(std::time::Duration::from_secs(5), startup)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let (shutdown, receiver) = watch::channel(false);
        let mapping_task = tokio::spawn(run_port_mapping(client.clone(), receiver));
        wait_for_mapping(&client, Some(45_000)).await;

        fixture_control("replace").await;
        wait_for_mapping(&client, Some(45_001)).await;
        fixture_control("drop").await;
        wait_for_mapping(&client, None).await;
        fixture_control("restore").await;
        wait_for_mapping(&client, Some(45_002)).await;

        shutdown.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(15), mapping_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        wait_for_mapping(&client, None).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if std::fs::read_to_string(&events_path)
                    .unwrap_or_default()
                    .lines()
                    .any(|line| line.starts_with("delete "))
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("NAT-PMP fixture did not observe orderly deletion");

        // Reacquire once more, then make libp2p publication fail while the
        // gateway lease is live. The mapper must still receive and acknowledge
        // its delete before the original publication error is returned.
        std::fs::write(&events_path, "").unwrap();
        let (_unused_shutdown, receiver) = watch::channel(false);
        let failed_mapping_task = tokio::spawn(run_port_mapping(client.clone(), receiver));
        wait_for_mapping(&client, Some(45_002)).await;
        client.shutdown().await.unwrap();
        p2p_task.await.unwrap().unwrap();
        fixture_control("replace").await;
        let error = tokio::time::timeout(std::time::Duration::from_secs(15), failed_mapping_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("publish automatic gateway mapping")
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if std::fs::read_to_string(&events_path)
                    .unwrap_or_default()
                    .lines()
                    .any(|line| line.starts_with("delete "))
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("NAT-PMP fixture did not observe deletion after publication failure");
    }
}
