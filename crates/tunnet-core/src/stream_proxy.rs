//! Inbound stream acceptor: TCP-proxy to the destination in the stream header.
//! Used when a client opens a stream to a subnet/hostname-route target via this gateway.

use std::sync::Arc;

use tokio::net::TcpStream;
use tunnet_common::policy::{FlowContext, FlowEndpoint, Protocol};

use crate::forward::{Decision, ForwardingStore, PolicyEngine};
use crate::stream::{AcceptedStream, StreamHandler, splice_bidirectional};

pub fn stream_handler(forwarding: ForwardingStore, policy: PolicyEngine) -> StreamHandler {
    Arc::new(move |accepted| {
        let forwarding = forwarding.clone();
        let policy = policy.clone();
        Box::pin(async move {
            handle_accepted(accepted, &forwarding, &policy).await;
        })
    })
}

pub(crate) fn stream_authorization(
    snap: &crate::forward::ForwardingSnapshot,
    policy: &PolicyEngine,
    network: uuid::Uuid,
    peer_hex: &str,
    dst_ip: Option<std::net::Ipv4Addr>,
    dst_port: u16,
) -> Option<Option<crate::forward::PostureAuthorization>> {
    let Ok(endpoint) = peer_hex.parse() else {
        return None;
    };
    if !snap.allows_network(network, endpoint) {
        return None;
    }
    let src = snap.peer_endpoint(network, endpoint)?;
    let flow = FlowContext {
        src,
        dst: dst_ip
            .and_then(|ip| snap.tables.by_network_ip.get(&(network, ip)))
            .and_then(|peer| snap.peer_endpoint(network, peer.endpoint))
            .unwrap_or_else(|| FlowEndpoint::external(dst_ip)),
        protocol: Protocol::Tcp,
        dst_port: Some(dst_port),
    };
    let binding = snap.binding(network, endpoint).unwrap();
    let peer = crate::forward::policy::PeerCtx {
        endpoint,
        hex: &binding.endpoint_hex,
        hostname: &binding.hostname,
        tags: &binding.tags,
        network_name: &binding.network_name,
    };
    match policy.evaluate_network_flow(
        snap,
        network,
        &peer,
        tunnet_common::policy::Direction::Inbound,
        &flow,
    ) {
        Decision::Allow { posture } => Some(posture),
        _ => None,
    }
}

fn authorize_stream(
    snap: &crate::forward::ForwardingSnapshot,
    policy: &PolicyEngine,
    network: uuid::Uuid,
    peer_hex: &str,
    dst_ip: Option<std::net::Ipv4Addr>,
    dst_port: u16,
) -> bool {
    stream_authorization(snap, policy, network, peer_hex, dst_ip, dst_port).is_some()
}

async fn until_revoked(
    forwarding: &ForwardingStore,
    policy: &PolicyEngine,
    network: uuid::Uuid,
    peer_hex: &str,
    host: &str,
    dst_ip: Option<std::net::Ipv4Addr>,
    port: u16,
) {
    let mut changes = forwarding.subscribe_changes();
    let epoch = forwarding.load().auth_epoch(network);
    loop {
        let snap = forwarding.load();
        #[cfg(feature = "direct")]
        let auth = snap.direct_auth.clone();
        #[cfg(feature = "direct")]
        let mut auth_changes = auth.as_ref().map(|auth| auth.subscribe_changes());
        if snap.auth_epoch(network) != epoch
            || !peer_hex
                .parse()
                .ok()
                .is_some_and(|peer| snap.allows_network(network, peer))
            || (dst_ip.is_some()
                && !authorize_stream(&snap, policy, network, peer_hex, dst_ip, port))
            || !target_allowed(&snap, network, host, dst_ip)
        {
            return;
        }
        let expiry = peer_hex.parse().ok().and_then(|peer| {
            stream_authorization(&snap, policy, network, peer_hex, dst_ip, port)
                .flatten()
                .and_then(|proof| proof.valid_until(&snap, network, peer))
        });
        #[cfg(feature = "direct")]
        let expiry = expiry
            .into_iter()
            .chain(auth.as_ref().and_then(|auth| {
                auth.network_expiry(peer_hex, network)
                    .into_iter()
                    .chain(auth.network_expiry(&snap.self_id.endpoint_hex, network))
                    .min()
            }))
            .min();
        tokio::select! {
            result = changes.changed() => if result.is_err() { return; },
            _ = async {
                #[cfg(feature = "direct")]
                if let Some(changes) = &mut auth_changes {
                    let _ = changes.changed().await;
                    return;
                }
                std::future::pending::<()>().await;
            } => {},
            _ = async {
                if let Some(expiry) = expiry {
                    let millis = (expiry.as_millisecond() - jiff::Timestamp::now().as_millisecond()).max(0);
                    tokio::time::sleep(std::time::Duration::from_millis(millis as u64)).await;
                    return;
                }
                std::future::pending::<()>().await;
            } => {},
        }
    }
}

fn target_allowed(
    snap: &crate::forward::ForwardingSnapshot,
    network: uuid::Uuid,
    host: &str,
    dst_ip: Option<std::net::Ipv4Addr>,
) -> bool {
    if dst_ip.is_some_and(|ip| !destination_isolated(snap, network, ip)) {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        snap.destination_allowed(network, ip) && snap.local_ip(network) != Some(ip)
    } else {
        let host = host.to_ascii_lowercase();
        snap.tables.advertised_hostnames.iter().any(|info| {
            info.peer.network_id == network
                && info.target_ip.is_none_or(|target| dst_ip == Some(target))
                && (info.hostname == host
                    || (info.is_wildcard
                        && host
                            .strip_suffix(&info.hostname)
                            .is_some_and(|prefix| prefix.ends_with('.'))))
        })
    }
}

fn destination_isolated(
    snap: &crate::forward::ForwardingSnapshot,
    network: uuid::Uuid,
    ip: std::net::Ipv4Addr,
) -> bool {
    snap.address_isolated(network, ip) && snap.local_ip(network) != Some(ip)
}

async fn handle_accepted(
    accepted: AcceptedStream,
    forwarding: &ForwardingStore,
    policy: &PolicyEngine,
) {
    let host = accepted.header.host.clone();
    let port = accepted.header.dst_port;
    let peer_hex = accepted.peer_hex;
    let network = accepted.header.network;
    let snap = forwarding.load();
    if !snap.allows_network(network, accepted.peer) {
        return;
    }

    if host == crate::ping::PING_HOST {
        let _ =
            crate::ping::handle_inbound_ping(&accepted.header, accepted.send, accepted.recv).await;
        return;
    }

    let (connect_host, dst_ip) = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if !snap.destination_allowed(network, ip) || snap.local_ip(network) == Some(ip) {
            tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
            return;
        }
        (host.clone(), Some(ip))
    } else if let Some(info) = snap.tables.advertised_hostnames.iter().find(|info| {
        info.peer.network_id == network
            && (info.hostname == host.to_ascii_lowercase()
                || (info.is_wildcard
                    && host
                        .to_ascii_lowercase()
                        .strip_suffix(&info.hostname)
                        .is_some_and(|prefix| prefix.ends_with('.'))))
    }) {
        if let Some(target) = info.target_ip {
            (target.to_string(), Some(target))
        } else {
            (host.clone(), None)
        }
    } else {
        tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
        return;
    };

    if !target_allowed(&snap, network, &host, dst_ip) {
        return;
    }
    let resolution = async {
        if let Some(ip) = dst_ip {
            return Some(ip);
        }
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::lookup_host((connect_host.as_str(), port)),
        )
        .await
        .ok()?
        .ok()?;
        let mut addresses: Vec<_> = resolved
            .filter_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        let snap = forwarding.load();
        addresses.into_iter().find(|ip| {
            target_allowed(&snap, network, &host, Some(*ip))
                && authorize_stream(&snap, policy, network, &peer_hex, Some(*ip), port)
        })
    };
    let Some(ip) = (tokio::select! {
        biased;
        _ = until_revoked(forwarding, policy, network, &peer_hex, &host, dst_ip, port) => None,
        result = resolution => result,
    }) else {
        return;
    };
    let dst_ip = Some(ip);
    let snap = forwarding.load();
    if !target_allowed(&snap, network, &host, dst_ip)
        || !authorize_stream(&snap, policy, network, &peer_hex, dst_ip, port)
    {
        return;
    }

    let revoked = until_revoked(forwarding, policy, network, &peer_hex, &host, dst_ip, port);
    let epoch = snap.auth_epoch(network);
    let proxy = async {
        let addr = std::net::SocketAddrV4::new(ip, port);
        let tcp = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!(%peer_hex, %addr, ?e, "TCP connect failed for inbound stream");
                return;
            }
            Err(_) => return,
        };
        if let Err(e) = tcp.set_nodelay(true) {
            tracing::debug!(?e, "set_nodelay failed");
        }

        tracing::info!(%peer_hex, %addr, "proxying inbound stream to LAN/target");
        let (tcp_read, tcp_write) = tcp.into_split();
        if let Err(e) =
            splice_bidirectional(accepted.recv, accepted.send, tcp_read, tcp_write).await
        {
            tracing::debug!(%peer_hex, %addr, ?e, "stream proxy closed");
        }
    };
    tokio::pin!(proxy);
    let guarded = std::future::poll_fn(|cx| {
        let gate = forwarding.authorization_gate();
        let _guard = gate.read();
        let snap = forwarding.load();
        if snap.auth_epoch(network) != epoch
            || !target_allowed(&snap, network, &host, dst_ip)
            || !authorize_stream(&snap, policy, network, &peer_hex, dst_ip, port)
        {
            return std::task::Poll::Ready(());
        }
        proxy.as_mut().poll(cx)
    });
    tokio::select! {
        biased;
        _ = revoked => {},
        _ = guarded => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::{ForwardingStore, SelfIdentity};
    use crate::routing::RoutingTable;
    use std::net::Ipv4Addr;
    use tunnet_common::policy::{
        Action, DefaultAction, IcmpPolicy, PolicyBundle, PolicyRule, PortRange,
        Protocol as PolProto, RuleScope, Selector,
    };
    use uuid::Uuid;

    fn setup_with(src: Selector, dst: Selector, rule_port: u16) -> (ForwardingStore, PolicyEngine) {
        let (forwarding, policy, _) = setup_with_routes(src, dst, rule_port);
        (forwarding, policy)
    }

    fn setup_with_routes(
        src: Selector,
        dst: Selector,
        rule_port: u16,
    ) -> (ForwardingStore, PolicyEngine, RoutingTable) {
        let routes = RoutingTable::new();
        let forwarding = ForwardingStore::new();
        routes.replace(
            &[
                tunnet_common::PeerEntry {
                    ip: Ipv4Addr::new(100, 64, 0, 2),
                    endpoint_id: "bb".repeat(32),
                    hostname: "peer".into(),
                    tags: vec![],
                    ssh_host_key: None,
                    posture: tunnet_common::PeerPosture::Unknown,
                },
                tunnet_common::PeerEntry {
                    ip: Ipv4Addr::new(100, 64, 0, 1),
                    endpoint_id: "aa".repeat(32),
                    hostname: "self".into(),
                    tags: vec![],
                    ssh_host_key: None,
                    posture: tunnet_common::PeerPosture::Unknown,
                },
            ],
            &[tunnet_common::SubnetRoute {
                cidr: "10.8.0.0/16".parse().unwrap(),
                via_endpoint_id: "aa".repeat(32),
                via_ip: "100.64.0.1".parse().unwrap(),
            }],
            &[tunnet_common::HostnameRoute {
                hostname: "safe.test".into(),
                via_endpoint_id: "aa".repeat(32),
                via_ip: "100.64.0.1".parse().unwrap(),
                is_wildcard: false,
                target_ip: None,
            }],
            &[],
            &Default::default(),
            &Default::default(),
            "net",
            Uuid::nil(),
            &"aa".repeat(32),
            1,
        );
        forwarding.set_managed_bundle(
            &routes,
            Uuid::nil(),
            PolicyBundle {
                rules: vec![PolicyRule {
                    src,
                    dst,
                    action: Action::Allow,
                    ports: vec![PortRange {
                        start: rule_port,
                        end: rule_port,
                    }],
                    protocol: Some(PolProto::Tcp),
                    priority: 100,
                    order_index: 0,
                    scope: RuleScope::Network,
                    enabled: true,
                    slug: Some("allow-port".into()),
                    src_posture: vec![],
                }],
                ssh_rules: vec![],
                version: 1,
                signature: String::new(),
                default_action: DefaultAction::Deny,
                icmp_policy: IcmpPolicy::Deny,
                postures: Default::default(),
                default_src_posture: vec![],
                posture_enforcement: None,
            },
            SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
                posture: tunnet_common::PeerPosture::Unknown,
            },
        );
        (forwarding, PolicyEngine::new(), routes)
    }

    #[rstest::rstest]
    #[case(None)]
    #[case(Some("10.9.0.2".parse().unwrap()))]
    fn hostname_target_cannot_enter_another_network(#[case] explicit: Option<Ipv4Addr>) {
        let (forwarding, policy, routes) = setup_with_routes(Selector::Any, Selector::Any, 443);
        let network_b = Uuid::from_u128(1);
        if let Some(target_ip) = explicit {
            let peers: Vec<_> = forwarding
                .load()
                .tables
                .by_network_ip
                .iter()
                .filter(|((net, _), _)| *net == Uuid::nil())
                .map(|(_, peer)| tunnet_common::PeerEntry {
                    ip: peer.ip,
                    endpoint_id: peer.endpoint_hex.clone(),
                    hostname: peer.hostname.clone(),
                    tags: peer.tags.clone(),
                    ssh_host_key: None,
                    posture: tunnet_common::PeerPosture::Unknown,
                })
                .collect();
            routes.replace(
                &peers,
                &[],
                &[tunnet_common::HostnameRoute {
                    hostname: "safe.test".into(),
                    via_endpoint_id: "aa".repeat(32),
                    via_ip: "100.64.0.1".parse().unwrap(),
                    is_wildcard: false,
                    target_ip: Some(target_ip),
                }],
                &[],
                &Default::default(),
                &Default::default(),
                "net",
                Uuid::nil(),
                &"aa".repeat(32),
                2,
            );
        }
        routes.replace_network_with_plan(
            network_b,
            &[tunnet_common::PeerEntry {
                ip: "10.9.0.2".parse().unwrap(),
                endpoint_id: "cc".repeat(32),
                hostname: "other-network".into(),
                tags: vec![],
                ssh_host_key: None,
                posture: tunnet_common::PeerPosture::Unknown,
            }],
            &Default::default(),
            "other-net",
            &"aa".repeat(32),
            1,
            Some("10.9.0.0/16".parse().unwrap()),
        );
        forwarding.republish(&routes);
        let snap = forwarding.load();
        drop(forwarding);
        let mut snap = Arc::try_unwrap(snap).ok().unwrap();
        Arc::make_mut(&mut snap.tables)
            .claims
            .push(crate::routing::RouteClaim {
                network: network_b,
                cidr: "10.9.0.0/16".parse().unwrap(),
                endpoint: "cc".repeat(32).parse().unwrap(),
                local: false,
            });
        assert!(
            snap.tables
                .advertised_hostnames
                .iter()
                .any(|route| route.hostname == "safe.test" && route.target_ip == explicit)
        );
        for ip in ["10.9.0.2", "10.9.0.7"] {
            assert!(!target_allowed(
                &snap,
                Uuid::nil(),
                "safe.test",
                Some(ip.parse().unwrap())
            ));
        }
        if explicit.is_none() {
            let public = "203.0.113.7".parse().unwrap();
            assert!(target_allowed(
                &snap,
                Uuid::nil(),
                "safe.test",
                Some(public)
            ));
            assert!(authorize_stream(
                &snap,
                &policy,
                Uuid::nil(),
                &"bb".repeat(32),
                Some(public),
                443
            ));
        }
    }

    #[test]
    fn stream_authorize_enforces_destination_port() {
        let (forwarding, policy) = setup_with(Selector::Any, Selector::Any, 443);
        let peer = "bb".repeat(32);
        let lan = Some(Ipv4Addr::new(10, 8, 0, 7));
        assert!(authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &peer,
            lan,
            443
        ));
        assert!(!authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &peer,
            lan,
            22
        ));
        assert!(!authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &peer,
            lan,
            80
        ));
        assert!(!authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &"cc".repeat(32),
            lan,
            443
        ));
    }

    #[test]
    fn stream_authorize_evaluates_destination_entity_not_self() {
        use ipnet::IpNet;
        let lan: IpNet = "10.8.0.0/16".parse().unwrap();
        let (forwarding, policy) = setup_with(Selector::Any, Selector::Cidr(lan), 443);
        let peer = "bb".repeat(32);
        assert!(authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &peer,
            Some(Ipv4Addr::new(10, 8, 0, 7)),
            443
        ));
        assert!(!authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::nil(),
            &peer,
            Some(Ipv4Addr::new(192, 168, 1, 7)),
            443
        ));
    }

    #[tokio::test]
    async fn stream_revocation_wakes_without_network_ambiguity_or_polling() {
        let (forwarding, policy) = setup_with(Selector::Any, Selector::Any, 443);
        let peer = "bb".repeat(32);
        let ip = "10.8.0.7".parse().unwrap();
        assert!(!authorize_stream(
            &forwarding.load(),
            &policy,
            Uuid::from_u128(1),
            &peer,
            Some(ip),
            443
        ));
        let revoked = until_revoked(
            &forwarding,
            &policy,
            Uuid::nil(),
            &peer,
            "10.8.0.7",
            Some(ip),
            443,
        );
        tokio::pin!(revoked);
        assert!(futures_util::poll!(revoked.as_mut()).is_pending());
        forwarding.clear_managed(&RoutingTable::new(), Uuid::nil());
        tokio::time::timeout(std::time::Duration::from_secs(1), revoked)
            .await
            .unwrap();
    }
}
