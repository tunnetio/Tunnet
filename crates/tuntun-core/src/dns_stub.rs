//! PeerDNS stub resolver — answers A queries for mesh names and hostname routes,
//! forwards everything else to upstream resolvers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_proto::op::{
    DEFAULT_MAX_PAYLOAD_LEN, Edns, Message, MessageType, OpCode, ResponseCode,
};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tuntun_common::DnsConfig;

use crate::routing::RoutingTable;

const TTL_SECS: u32 = 30;
/// Recv buffer sized for modern EDNS payloads (default max is 1232).
const UDP_BUF: usize = DEFAULT_MAX_PAYLOAD_LEN as usize;

pub fn spawn(
    bind: SocketAddr,
    routes: RoutingTable,
    dns: DnsConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(bind, routes, dns).await {
            tracing::error!(?e, %bind, "PeerDNS stub exited");
        }
    })
}

async fn bind_udp_with_retry(bind: SocketAddr) -> anyhow::Result<UdpSocket> {
    const ATTEMPTS: u32 = 20;
    let mut last_err = None;
    for attempt in 1..=ATTEMPTS {
        match UdpSocket::bind(bind).await {
            Ok(sock) => return Ok(sock),
            Err(e) => {
                tracing::debug!(?e, %bind, attempt, "PeerDNS bind retry");
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
            }
        }
    }
    Err(last_err
        .map(Into::into)
        .unwrap_or_else(|| anyhow::anyhow!("PeerDNS bind failed")))
    .with_context(|| format!("bind PeerDNS UDP {bind}"))
}

async fn run(bind: SocketAddr, routes: RoutingTable, dns: DnsConfig) -> anyhow::Result<()> {
    // On Windows the TUN IP is often not bindable for a few hundred ms after
    // adapter create. Prefer 0.0.0.0:53 first — it still receives packets to
    // the overlay IP — then fall back to the TUN address with retries.
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, bind.port()));
    let sock = match UdpSocket::bind(any).await {
        Ok(s) => {
            tracing::info!(%any, via = %bind, suffix = %dns.suffix, "PeerDNS stub listening");
            s
        }
        Err(e) => {
            tracing::debug!(?e, %any, "PeerDNS wildcard bind failed; trying TUN IP");
            let s = bind_udp_with_retry(bind).await?;
            tracing::info!(%bind, suffix = %dns.suffix, "PeerDNS stub listening");
            s
        }
    };
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let request = buf[..n].to_vec();
        let sock = sock.clone();
        let routes = routes.clone();
        let upstream = dns.upstream.clone();
        let suffix = dns.suffix.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_query(sock, peer, &request, &routes, &suffix, &upstream).await {
                tracing::debug!(?e, %peer, "dns query failed");
            }
        });
    }
}

async fn handle_query(
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    bytes: &[u8],
    routes: &RoutingTable,
    suffix: &str,
    upstream: &[IpAddr],
) -> anyhow::Result<()> {
    let query = Message::from_bytes(bytes).context("decode dns")?;
    if query.metadata.message_type != MessageType::Query || query.metadata.op_code != OpCode::Query
    {
        return Ok(());
    }
    let Some(question) = query.queries.first() else {
        return Ok(());
    };

    let qname = &question.name;
    let qtype = question.query_type;
    let name_str = qname.to_string();

    let our_zone = name_in_suffix(qname, suffix)
        || routes
            .lookup_hostname_route(name_str.trim_end_matches('.'))
            .is_some();

    if our_zone && (qtype == RecordType::A || qtype == RecordType::AAAA) {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.authoritative = true;
        response.metadata.recursion_available = true;
        response.queries = query.queries.clone();
        echo_edns(&query, &mut response);

        if qtype == RecordType::A {
            if let Some(ip) = routes.resolve_dns_a(&name_str) {
                let rr = Record::from_rdata(qname.clone(), TTL_SECS, RData::A(A(ip)));
                response.add_answer(rr);
                response.metadata.response_code = ResponseCode::NoError;
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        } else {
            // No AAAA yet — NODATA (NOERROR, empty answer) for our zone.
            response.metadata.response_code = ResponseCode::NoError;
        }

        let out = response.to_bytes().context("encode dns")?;
        sock.send_to(&out, peer).await?;
        return Ok(());
    }

    if let Some(answer) = forward_upstream(bytes, query.metadata.id, upstream).await? {
        sock.send_to(&answer, peer).await?;
    }
    Ok(())
}

/// RFC 6891: if the request carried OPT, the response must include OPT.
fn echo_edns(query: &Message, response: &mut Message) {
    if let Some(req_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(req_edns.max_payload().max(DEFAULT_MAX_PAYLOAD_LEN));
        edns.set_version(0);
        response.set_edns(edns);
    }
}

fn name_in_suffix(qname: &Name, suffix: &str) -> bool {
    let Ok(zone) = Name::from_utf8(suffix) else {
        return false;
    };
    zone.zone_of(qname) || zone == *qname
}

async fn forward_upstream(
    query: &[u8],
    expect_id: u16,
    upstream: &[IpAddr],
) -> anyhow::Result<Option<Vec<u8>>> {
    if upstream.is_empty() {
        return Ok(None);
    }
    for addr in upstream {
        let target = SocketAddr::new(*addr, 53);
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
            continue;
        };
        if sock.send_to(query, target).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; UDP_BUF];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => match Message::from_bytes(&buf[..n]) {
                Ok(msg)
                    if msg.metadata.message_type == MessageType::Response
                        && msg.metadata.id == expect_id =>
                {
                    return Ok(Some(buf[..n].to_vec()));
                }
                Ok(msg) => {
                    tracing::debug!(
                        %addr,
                        id = msg.metadata.id,
                        expect_id,
                        ty = ?msg.metadata.message_type,
                        "upstream DNS reply rejected"
                    );
                }
                Err(e) => {
                    tracing::debug!(?e, %addr, "upstream DNS decode failed");
                }
            },
            _ => continue,
        }
    }
    Ok(None)
}

/// Bind address for the stub on the TUN IP.
pub fn bind_addr(tun_ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::from((tun_ip, 53))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn zone_match_uses_name_hierarchy() {
        let host = Name::from_str("db.office.tuntun.").unwrap();
        let bare = Name::from_str("tuntun.").unwrap();
        assert!(name_in_suffix(&host, "tuntun"));
        assert!(name_in_suffix(&bare, "tuntun"));
        assert!(!name_in_suffix(
            &Name::from_str("evil-tuntun.com.").unwrap(),
            "tuntun"
        ));
    }

    #[test]
    fn response_uses_public_metadata_fields() {
        let mut msg = Message::response(42, OpCode::Query);
        msg.metadata.authoritative = true;
        msg.metadata.recursion_available = true;
        msg.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(msg.metadata.id, 42);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.metadata.id, 42);
        assert!(decoded.metadata.authoritative);
        assert_eq!(decoded.metadata.response_code, ResponseCode::NXDomain);
    }
}
