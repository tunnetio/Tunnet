//! PeerDNS stub resolver - answers A/AAAA/PTR/SOA/NS for mesh names and hostname routes,
//! forwards everything else to upstream resolvers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_proto::op::{
    DEFAULT_MAX_PAYLOAD_LEN, Edns, Message, MessageType, OpCode, ResponseCode,
};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, NS, PTR, SOA, TXT},
};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tunnet_common::DnsConfig;

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
    // Prefer 0.0.0.0:53 so packets to the magic IP (and TUN IP) are received.
    // Fall back to the configured bind (magic IP) with retries.
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, bind.port()));
    let sock = match UdpSocket::bind(any).await {
        Ok(s) => {
            tracing::info!(
                %any,
                via = %bind,
                magic = %dns.magic_ip,
                suffix = %dns.suffix,
                "PeerDNS stub listening"
            );
            s
        }
        Err(e) => {
            tracing::debug!(?e, %any, "PeerDNS wildcard bind failed; trying magic IP");
            let magic_bind = SocketAddr::from((dns.magic_ip, bind.port()));
            let s = match bind_udp_with_retry(magic_bind).await {
                Ok(s) => s,
                Err(_) => bind_udp_with_retry(bind).await?,
            };
            tracing::info!(%bind, magic = %dns.magic_ip, suffix = %dns.suffix, "PeerDNS stub listening");
            s
        }
    };
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if is_transient_udp_recv_error(&e) => {
                tracing::debug!(?e, %bind, "PeerDNS ignoring transient UDP recv error");
                continue;
            }
            Err(e) => return Err(e).context("PeerDNS recv_from"),
        };
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

fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    )
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

    if our_zone
        && matches!(
            qtype,
            RecordType::A | RecordType::AAAA | RecordType::SOA | RecordType::NS | RecordType::TXT
        )
    {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.authoritative = true;
        response.metadata.recursion_available = true;
        response.queries = query.queries.clone();
        echo_edns(&query, &mut response);

        match qtype {
            RecordType::A => {
                if let Some(ip) = routes.resolve_dns_a(&name_str) {
                    routes.remember_dns_synth(&name_str, ip);
                    let rr = Record::from_rdata(qname.clone(), TTL_SECS, RData::A(A(ip)));
                    response.add_answer(rr);
                    response.metadata.response_code = ResponseCode::NoError;
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            RecordType::AAAA => {
                // No AAAA yet - NODATA for our zone.
                response.metadata.response_code = ResponseCode::NoError;
            }
            RecordType::TXT => {
                if let Some(key) = routes.resolve_dns_txt(&name_str) {
                    let txt = TXT::new(vec![format!("ssh-hostkey={key}")]);
                    let rr = Record::from_rdata(qname.clone(), TTL_SECS, RData::TXT(txt));
                    response.add_answer(rr);
                    response.metadata.response_code = ResponseCode::NoError;
                } else if routes.resolve_dns_a(&name_str).is_some() {
                    // Name exists but no host key yet - NODATA.
                    response.metadata.response_code = ResponseCode::NoError;
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            RecordType::SOA => {
                if let Some(soa) = zone_soa(qname, suffix, routes) {
                    response.add_answer(soa);
                    response.metadata.response_code = ResponseCode::NoError;
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            RecordType::NS => {
                if let Some(ns) = zone_ns(qname, suffix) {
                    response.add_answer(ns);
                    response.metadata.response_code = ResponseCode::NoError;
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            _ => unreachable!(),
        }

        let out = response.to_bytes().context("encode dns")?;
        sock.send_to(&out, peer).await?;
        return Ok(());
    }

    // PTR for in-addr.arpa reverse of mesh peers.
    if qtype == RecordType::PTR
        && let Some(ip) = parse_in_addr_arpa(qname)
    {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.authoritative = true;
        response.metadata.recursion_available = true;
        response.queries = query.queries.clone();
        echo_edns(&query, &mut response);

        if let Some(fqdn) = routes.resolve_dns_ptr(ip) {
            let ptr_name = Name::from_utf8(format!("{fqdn}."))
                .unwrap_or_else(|_| Name::from_utf8("invalid.").expect("literal"));
            let rr = Record::from_rdata(qname.clone(), TTL_SECS, RData::PTR(PTR(ptr_name)));
            response.add_answer(rr);
            response.metadata.response_code = ResponseCode::NoError;
        } else if routes.is_magic_dns_destination(&ip) {
            let ns = Name::from_utf8(format!("ns.{suffix}."))
                .unwrap_or_else(|_| Name::from_utf8("ns.tunnet.").expect("literal"));
            let rr = Record::from_rdata(qname.clone(), TTL_SECS, RData::PTR(PTR(ns)));
            response.add_answer(rr);
            response.metadata.response_code = ResponseCode::NoError;
        } else {
            // Not our reverse zone - forward.
            if let Some(answer) = forward_upstream(bytes, query.metadata.id, upstream).await? {
                sock.send_to(&answer, peer).await?;
            }
            return Ok(());
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

fn zone_soa(qname: &Name, suffix: &str, routes: &RoutingTable) -> Option<Record> {
    if !name_in_suffix(qname, suffix) {
        return None;
    }
    let mname = Name::from_utf8(format!("ns.{suffix}.")).ok()?;
    let rname = Name::from_utf8(format!("hostmaster.{suffix}.")).ok()?;
    let serial = routes.version().max(1) as u32;
    let soa = SOA::new(mname, rname, serial, 300, 60, 86400, TTL_SECS);
    Some(Record::from_rdata(qname.clone(), TTL_SECS, RData::SOA(soa)))
}

fn zone_ns(qname: &Name, suffix: &str) -> Option<Record> {
    if !name_in_suffix(qname, suffix) {
        return None;
    }
    let ns = Name::from_utf8(format!("ns.{suffix}.")).ok()?;
    Some(Record::from_rdata(
        qname.clone(),
        TTL_SECS,
        RData::NS(NS(ns)),
    ))
}

/// Parse `d.c.b.a.in-addr.arpa.` → `a.b.c.d`.
fn parse_in_addr_arpa(qname: &Name) -> Option<Ipv4Addr> {
    let s = qname.to_string().trim_end_matches('.').to_ascii_lowercase();
    let rest = s.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[3].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let c: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[0].parse().ok()?;
    Some(Ipv4Addr::new(a, b, c, d))
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

/// Bind address for the stub - prefers the PeerDNS magic IP.
pub fn bind_addr(magic_or_tun_ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::from((magic_or_tun_ip, 53))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn zone_match_uses_name_hierarchy() {
        let host = Name::from_str("db.office.tunnet.").unwrap();
        let bare = Name::from_str("tunnet.").unwrap();
        assert!(name_in_suffix(&host, "tunnet"));
        assert!(name_in_suffix(&bare, "tunnet"));
        assert!(!name_in_suffix(
            &Name::from_str("evil-tunnet.com.").unwrap(),
            "tunnet"
        ));
    }

    #[test]
    fn parse_reverse_arpa() {
        let n = Name::from_str("53.100.100.100.in-addr.arpa.").unwrap();
        assert_eq!(
            parse_in_addr_arpa(&n),
            Some(Ipv4Addr::new(100, 100, 100, 53))
        );
        let peer = Name::from_str("10.64.100.100.in-addr.arpa.").unwrap();
        assert_eq!(
            parse_in_addr_arpa(&peer),
            Some(Ipv4Addr::new(100, 100, 64, 10))
        );
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

    #[test]
    fn windows_udp_connreset_is_transient() {
        let err = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(is_transient_udp_recv_error(&err));
        let fatal = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert!(!is_transient_udp_recv_error(&fatal));
    }
}
