//! Inbound stream acceptor: TCP-proxy to the destination in the stream header.
//! Used when a client opens a stream to a subnet/hostname-route target via this gateway.

use std::sync::Arc;

use tokio::net::TcpStream;
use tunnet_common::policy::{Direction, Protocol};

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

/// Flow authorize a proxied stream against real TCP/port context before dialing
/// the LAN target. Mirrors the outbound TUN verdict for the same destination.
fn authorize_stream(acl: &AclEngine, peer_hex: &str, dst_port: u16) -> Result<(), FlowDeny> {
    if acl.allow_flow(peer_hex, Direction::Outbound, Protocol::Tcp, Some(dst_port)) {
        Ok(())
    } else {
        Err(FlowDeny { dst_port })
    }
}

#[derive(Debug)]
struct FlowDeny {
    dst_port: u16,
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

    let connect_host = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if !routes.is_advertised_destination(&ip) {
            tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
            return;
        }
        host.clone()
    } else if let Some(info) = routes.lookup_hostname_route(&host) {
        if !routes.is_advertised_hostname(&host) {
            tracing::warn!(%peer_hex, %host, port, "refusing stream: not our hostname route");
            return;
        }
        if let Some(target) = info.target_ip {
            target.to_string()
        } else {
            host.clone()
        }
    } else if routes.is_advertised_hostname(&host) {
        host.clone()
    } else {
        tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
        return;
    };

    if let Err(deny) = authorize_stream(acl, &peer_hex, port) {
        tracing::warn!(%peer_hex, %host, dst_port = deny.dst_port, "refusing stream: flow policy denies TCP destination port");
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

    fn engine_with(rule_port: u16) -> AclEngine {
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
                    src: Selector::Any,
                    dst: Selector::Any,
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
        let acl = engine_with(443);
        let peer = "bb".repeat(32);
        assert!(authorize_stream(&acl, &peer, 443).is_ok());
        assert!(authorize_stream(&acl, &peer, 22).is_err());
        assert!(authorize_stream(&acl, &peer, 80).is_err());
    }
}
