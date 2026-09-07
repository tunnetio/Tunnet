//! Inbound stream acceptor: TCP-proxy to the destination in the stream header.
//! Used when a client opens a stream to a subnet/hostname-route target via this gateway.

use std::sync::Arc;

use tokio::net::TcpStream;
use tunnet_common::policy::{FlowContext, FlowEndpoint, Protocol};

use crate::acl::AclEngine;
use crate::routing::RoutingTable;
use crate::stream::{AcceptedStream, StreamHandler, splice_bidirectional};

pub fn stream_handler(routes: RoutingTable, acl: AclEngine) -> StreamHandler {
    Arc::new(move |accepted| {
        let routes = routes.clone();
        let acl = acl.clone();
        Box::pin(async move {
            handle_accepted(accepted, &routes, &acl).await;
        })
    })
}

/// Authorize a proxied stream against the real flow: the requesting peer as
/// source principal, the LAN/hostname target as destination. Source posture is
/// attested by the initiating node on its own egress; the gateway authorizes
/// the destination.
fn authorize_stream(
    acl: &AclEngine,
    peer_hex: &str,
    dst_ip: Option<std::net::Ipv4Addr>,
    dst_port: u16,
) -> bool {
    let flow = FlowContext {
        src: acl.peer_endpoint(peer_hex),
        dst: FlowEndpoint::external(dst_ip),
        protocol: Protocol::Tcp,
        dst_port: Some(dst_port),
        src_posture_ok: true,
    };
    acl.allow_flow(&flow, peer_hex)
}

async fn handle_accepted(accepted: AcceptedStream, routes: &RoutingTable, acl: &AclEngine) {
    let host = accepted.header.host.clone();
    let port = accepted.header.dst_port;
    let peer_hex = accepted.peer_hex;

    if host == crate::ping::PING_HOST {
        let _ =
            crate::ping::handle_inbound_ping(&accepted.header, accepted.send, accepted.recv).await;
        return;
    }

    let (connect_host, dst_ip) = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if !routes.is_advertised_destination(&ip) {
            tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
            return;
        }
        (host.clone(), Some(ip))
    } else if let Some(info) = routes.lookup_hostname_route(&host) {
        if !routes.is_advertised_hostname(&host) {
            tracing::warn!(%peer_hex, %host, port, "refusing stream: not our hostname route");
            return;
        }
        if let Some(target) = info.target_ip {
            (target.to_string(), Some(target))
        } else {
            (host.clone(), None)
        }
    } else if routes.is_advertised_hostname(&host) {
        (host.clone(), None)
    } else {
        tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
        return;
    };

    if !authorize_stream(acl, &peer_hex, dst_ip, port) {
        tracing::warn!(%peer_hex, %host, port, "refusing stream: flow policy denies the destination");
        return;
    }

    let addr = format!("{connect_host}:{port}");
    let tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%peer_hex, %addr, ?e, "TCP connect failed for inbound stream");
            return;
        }
    };
    if let Err(e) = tcp.set_nodelay(true) {
        tracing::debug!(?e, "set_nodelay failed");
    }

    tracing::info!(%peer_hex, %addr, "proxying inbound stream to LAN/target");
    let (tcp_read, tcp_write) = tcp.into_split();
    if let Err(e) = splice_bidirectional(accepted.recv, accepted.send, tcp_read, tcp_write).await {
        tracing::debug!(%peer_hex, %addr, ?e, "stream proxy closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tunnet_common::policy::{
        Action, DefaultAction, IcmpPolicy, PolicyBundle, PolicyRule, PortRange,
        Protocol as PolProto, RuleScope, Selector,
    };

    fn engine_with(src: Selector, dst: Selector, rule_port: u16) -> AclEngine {
        let routes = RoutingTable::new();
        AclEngine::new(
            crate::acl::SelfIdentity {
                endpoint_hex: "aa".repeat(32),
                ip: Ipv4Addr::new(100, 64, 0, 1),
                tags: vec![],
                network: "net".into(),
            },
            routes,
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
        )
    }

    #[test]
    fn stream_authorize_enforces_destination_port() {
        let acl = engine_with(Selector::Any, Selector::Any, 443);
        let peer = "bb".repeat(32);
        let lan = Some(Ipv4Addr::new(10, 8, 0, 7));
        assert!(authorize_stream(&acl, &peer, lan, 443));
        assert!(!authorize_stream(&acl, &peer, lan, 22));
        assert!(!authorize_stream(&acl, &peer, lan, 80));
    }

    #[test]
    fn stream_authorize_evaluates_destination_entity_not_self() {
        use ipnet::IpNet;
        let lan: IpNet = "10.8.0.0/16".parse().unwrap();
        let acl = engine_with(Selector::Any, Selector::Cidr(lan), 443);
        let peer = "bb".repeat(32);
        assert!(authorize_stream(
            &acl,
            &peer,
            Some(Ipv4Addr::new(10, 8, 0, 7)),
            443
        ));
        assert!(!authorize_stream(
            &acl,
            &peer,
            Some(Ipv4Addr::new(192, 168, 1, 7)),
            443
        ));
    }
}
