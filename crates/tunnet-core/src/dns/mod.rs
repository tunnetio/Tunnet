//! PeerDNS stub: authoritative mesh answers, Hickory for everything else.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tunnet_common::DnsConfig;

use crate::routing::RoutingTable;

mod nameserver;
mod peerdns;
mod upstream;

pub use nameserver::{UpstreamSource, parse_upstream};
pub use upstream::{
    HickoryLookup, build_resolver, capture_underlay_upstream_specs, filter_self_nameservers,
    system_nameservers_excluding, tunnet_resolver_opts, with_underlay_upstream,
};

use peerdns::{answer_owned, answer_ptr, base_response, owned_forward_name, parse_in_addr_arpa};
use upstream::{ExternalLookup, map_external};

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

pub fn bind_addr(magic_or_tun_ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::from((magic_or_tun_ip, 53))
}

/// Whether the `bind` fallback is a genuinely different socket from the
/// magic-IP attempt.
///
/// Callers normally pass `bind_addr(magic_ip)`, so the two are usually the same
/// socket. Retrying an identical address a second time cannot succeed and only
/// doubles the delay before the error surfaces: 40 attempts over ~21s instead
/// of 20 over ~10s. Measured on Android, where neither bind can ever succeed
/// (the magic IP is not on the TUN and port 53 is privileged).
fn fallback_is_distinct(magic_bind: SocketAddr, bind: SocketAddr) -> bool {
    magic_bind != bind
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
    // Loop-prevention invariant: resolve a `"system"` upstream to the
    // explicit underlay snapshot NOW, before the agent installs the osdns
    // overlay that points the OS at PeerDNS. `build_resolver` additionally
    // filters our own magic IP so even a post-overlay rebuild cannot loop.
    let dns = with_underlay_upstream(&dns);
    let lookup = match HickoryLookup::from_dns_config(&dns) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            tracing::error!(
                ?e,
                "failed to build Hickory resolver; external DNS will SERVFAIL"
            );
            return Err(e);
        }
    };

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
                Err(e) if !fallback_is_distinct(magic_bind, bind) => return Err(e),
                Err(_) => bind_udp_with_retry(bind).await?,
            };
            tracing::info!(%bind, magic = %dns.magic_ip, suffix = %dns.suffix, "PeerDNS stub listening");
            s
        }
    };
    let sock = Arc::new(sock);
    let suffix = Arc::new(dns.suffix);
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
        let suffix = suffix.clone();
        let lookup = lookup.clone();
        tokio::spawn(async move {
            let out = process_query(&request, &routes, &suffix, lookup.as_ref()).await;
            if let Err(e) = sock.send_to(&out, peer).await {
                tracing::debug!(?e, %peer, "dns send failed");
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

async fn process_query(
    bytes: &[u8],
    routes: &RoutingTable,
    suffix: &str,
    lookup: &impl ExternalLookup,
) -> Vec<u8> {
    match answer_query(bytes, routes, suffix, lookup).await {
        Ok(msg) => msg.to_bytes().unwrap_or_else(|_| formerr_from_raw(bytes)),
        Err(raw) => raw,
    }
}

async fn answer_query(
    bytes: &[u8],
    routes: &RoutingTable,
    suffix: &str,
    lookup: &impl ExternalLookup,
) -> Result<Message, Vec<u8>> {
    let query = match Message::from_bytes(bytes) {
        Ok(q) => q,
        Err(_) => return Err(formerr_from_raw(bytes)),
    };

    if query.metadata.op_code != OpCode::Query {
        let mut r = base_response(&query, false);
        r.metadata.response_code = ResponseCode::NotImp;
        r.metadata.authoritative = false;
        return Ok(r);
    }
    if query.metadata.message_type != MessageType::Query {
        let mut r = base_response(&query, false);
        r.metadata.response_code = ResponseCode::FormErr;
        return Ok(r);
    }
    let Some(question) = query.queries.first() else {
        let mut r = base_response(&query, false);
        r.metadata.response_code = ResponseCode::FormErr;
        return Ok(r);
    };

    let qname = &question.name;
    let qtype = question.query_type;
    let name_str = qname.to_string();

    if qtype == RecordType::PTR
        && let Some(ip) = parse_in_addr_arpa(qname)
    {
        if let Some(owned) = answer_ptr(&query, qname, ip, suffix, routes) {
            return Ok(owned);
        }
        return Ok(external_lookup(&query, qname.clone(), qtype, lookup).await);
    }

    if owned_forward_name(qname, &name_str, suffix, routes) {
        return Ok(answer_owned(
            &query, qname, qtype, &name_str, suffix, routes,
        ));
    }

    Ok(external_lookup(&query, qname.clone(), qtype, lookup).await)
}

async fn external_lookup(
    query: &Message,
    qname: hickory_proto::rr::Name,
    qtype: RecordType,
    lookup: &impl ExternalLookup,
) -> Message {
    let (code, records) = map_external(lookup.lookup(qname, qtype).await);
    let mut response = base_response(query, false);
    response.metadata.response_code = code;
    for rec in records {
        response.add_answer(rec);
    }
    response
}

fn formerr_from_raw(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 12 {
        return Vec::new();
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let mut msg = Message::response(id, OpCode::Query);
    msg.metadata.response_code = ResponseCode::FormErr;
    msg.metadata.recursion_available = true;
    msg.to_bytes().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RData, Record, rdata::A, rdata::MX};
    use tunnet_common::{DeviceProfile, DnsConfig, PeerEntry};
    use uuid::Uuid;

    use super::nameserver::connection_summary;
    use super::peerdns::name_in_suffix;
    use super::upstream::{
        ExtLookupFut, ExternalAnswer, ExternalLookup, filter_self_nameservers,
        tunnet_resolver_opts, with_underlay_upstream,
    };

    struct MockLookup {
        calls: Mutex<Vec<(String, RecordType)>>,
        answer: ExternalAnswer,
    }

    impl MockLookup {
        fn new(answer: ExternalAnswer) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                answer,
            }
        }
        fn called(&self) -> Vec<(String, RecordType)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ExternalLookup for MockLookup {
        fn lookup(&self, name: Name, qtype: RecordType) -> ExtLookupFut<'_> {
            self.calls.lock().unwrap().push((name.to_string(), qtype));
            let answer = match &self.answer {
                ExternalAnswer::Records(r) => ExternalAnswer::Records(r.clone()),
                ExternalAnswer::NxDomain => ExternalAnswer::NxDomain,
                ExternalAnswer::NoData => ExternalAnswer::NoData,
                ExternalAnswer::ServFail => ExternalAnswer::ServFail,
            };
            Box::pin(async move { answer })
        }
    }

    fn query_bytes(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg.to_bytes().unwrap()
    }

    fn peer(endpoint: &str, ip: &str, hostname: &str) -> PeerEntry {
        PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: endpoint.to_string(),
            hostname: hostname.to_string(),
            tags: vec![],
            ssh_host_key: Some("ssh-ed25519 AAAA".into()),
        }
    }

    fn routes() -> RoutingTable {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        table.replace(
            &[peer(&self_id, "100.64.0.2", "desktop")],
            &[],
            &[],
            &[],
            &DeviceProfile::default(),
            &DnsConfig::default(),
            "office",
            Uuid::nil(),
            &self_id,
            1,
        );
        table
    }

    async fn run(bytes: &[u8], lookup: &MockLookup) -> Message {
        let table = routes();
        answer_query(bytes, &table, "tunnet", lookup)
            .await
            .unwrap_or_else(|raw| Message::from_bytes(&raw).unwrap())
    }

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
    }

    #[test]
    fn windows_udp_connreset_is_transient() {
        let err = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(is_transient_udp_recv_error(&err));
        let fatal = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert!(!is_transient_udp_recv_error(&fatal));
    }

    #[tokio::test]
    async fn mesh_names_never_hit_upstream() {
        let lookup = MockLookup::new(ExternalAnswer::ServFail);
        let q = query_bytes("desktop.tunnet.", RecordType::A, 9);
        let r = run(&q, &lookup).await;
        assert!(lookup.called().is_empty());
        assert!(r.metadata.authoritative);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
    }

    #[tokio::test]
    async fn mesh_mx_is_nodata_not_upstream() {
        let lookup = MockLookup::new(ExternalAnswer::Records(vec![]));
        let q = query_bytes("desktop.tunnet.", RecordType::MX, 3);
        let r = run(&q, &lookup).await;
        assert!(lookup.called().is_empty());
        assert!(r.metadata.authoritative);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[tokio::test]
    async fn unknown_mesh_name_is_nxdomain() {
        let lookup = MockLookup::new(ExternalAnswer::ServFail);
        let q = query_bytes("nope.tunnet.", RecordType::A, 1);
        let r = run(&q, &lookup).await;
        assert!(lookup.called().is_empty());
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn external_a_forwarding() {
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))));
        let lookup = MockLookup::new(ExternalAnswer::Records(vec![rec]));
        let q = query_bytes("example.com.", RecordType::A, 42);
        let r = run(&q, &lookup).await;
        assert_eq!(lookup.called()[0].1, RecordType::A);
        assert!(!r.metadata.authoritative);
        assert_eq!(r.metadata.id, 42);
        assert!(r.metadata.recursion_available);
        assert_eq!(r.answers.len(), 1);
    }

    #[tokio::test]
    async fn external_mx_forwarding() {
        let name = Name::from_str("example.com.").unwrap();
        let mx = MX::new(10, Name::from_str("mail.example.com.").unwrap());
        let rec = Record::from_rdata(name, 60, RData::MX(mx));
        let lookup = MockLookup::new(ExternalAnswer::Records(vec![rec]));
        let q = query_bytes("example.com.", RecordType::MX, 7);
        let r = run(&q, &lookup).await;
        assert_eq!(lookup.called()[0].1, RecordType::MX);
        assert_eq!(r.answers.len(), 1);
        assert!(!r.metadata.authoritative);
    }

    #[tokio::test]
    async fn nxdomain_vs_nodata() {
        let nx = MockLookup::new(ExternalAnswer::NxDomain);
        let r = run(&query_bytes("missing.test.", RecordType::A, 1), &nx).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);

        let empty = MockLookup::new(ExternalAnswer::NoData);
        let r = run(&query_bytes("empty.test.", RecordType::TXT, 2), &empty).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[tokio::test]
    async fn ptr_txt_soa_ns_mesh() {
        let lookup = MockLookup::new(ExternalAnswer::ServFail);
        let table = routes();
        let ip = table.resolve_dns_a("desktop.tunnet.").unwrap();
        let ptr = format!(
            "{}.{}.{}.{}.in-addr.arpa.",
            ip.octets()[3],
            ip.octets()[2],
            ip.octets()[1],
            ip.octets()[0]
        );
        let r = run(&query_bytes(&ptr, RecordType::PTR, 1), &lookup).await;
        assert!(lookup.called().is_empty());
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(!r.answers.is_empty());

        let txt = run(&query_bytes("desktop.tunnet.", RecordType::TXT, 2), &lookup).await;
        assert!(!txt.answers.is_empty());

        let soa = run(&query_bytes("tunnet.", RecordType::SOA, 3), &lookup).await;
        assert!(!soa.answers.is_empty());
        let ns = run(&query_bytes("tunnet.", RecordType::NS, 4), &lookup).await;
        assert!(!ns.answers.is_empty());
    }

    #[tokio::test]
    async fn malformed_query_is_formerr() {
        let lookup = MockLookup::new(ExternalAnswer::ServFail);
        let mut raw = query_bytes("example.com.", RecordType::A, 99);
        raw.truncate(8);
        raw.extend_from_slice(&[0xff; 20]);
        let out = process_query(&raw, &routes(), "tunnet", &lookup).await;
        if out.is_empty() {
            return;
        }
        let msg = Message::from_bytes(&out).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::FormErr);
    }

    #[test]
    fn resolver_opts_enable_tcp_fallback_and_cache() {
        let opts = tunnet_resolver_opts(false);
        assert!(opts.try_tcp_on_error);
        assert!(opts.edns0);
        assert!(opts.preserve_intermediates);
        assert_eq!(opts.num_concurrent_reqs, 2);
        assert_eq!(opts.cache_size, 32);
        assert!(!opts.validate);
        let on = tunnet_resolver_opts(true);
        assert!(on.validate);
    }

    #[test]
    fn loop_prevention_filters_peerdns_magic_from_candidates() {
        let magic = Ipv4Addr::new(100, 100, 100, 53);
        let filtered = filter_self_nameservers(
            [
                std::net::IpAddr::V4(magic),
                std::net::IpAddr::from([1, 1, 1, 1]),
                std::net::IpAddr::V4(magic),
            ],
            magic,
        );
        assert_eq!(filtered, vec![std::net::IpAddr::from([1, 1, 1, 1])]);
        // A post-overlay system state pointing only at PeerDNS leaves
        // nothing usable; the resolver must fail closed instead of looping.
        assert!(filter_self_nameservers([std::net::IpAddr::V4(magic)], magic).is_empty());
    }

    /// The fallback must not repeat the attempt that just failed. With the
    /// standard wiring (`bind_addr(magic_ip)`) both sockets are identical, so
    /// without this guard the bind is retried 40 times instead of 20, doubling
    /// the time before the error surfaces.
    #[test]
    fn fallback_is_skipped_when_it_would_repeat_the_same_socket() {
        let magic: Ipv4Addr = "169.254.0.53".parse().unwrap();
        let bind = bind_addr(magic);
        let magic_bind = SocketAddr::from((magic, bind.port()));
        assert!(
            !fallback_is_distinct(magic_bind, bind),
            "standard wiring yields the same socket, so the fallback is useless"
        );
    }

    #[test]
    fn fallback_still_runs_for_a_genuinely_different_socket() {
        let magic_bind = SocketAddr::from(("169.254.0.53".parse::<Ipv4Addr>().unwrap(), 53));
        let other = SocketAddr::from(("100.95.248.22".parse::<Ipv4Addr>().unwrap(), 53));
        assert!(fallback_is_distinct(magic_bind, other));
    }

    #[test]
    fn underlay_snapshot_never_selects_peerdns_itself() {
        let dns = DnsConfig {
            upstream: vec!["system".into()],
            ..DnsConfig::default()
        };
        assert_eq!(dns.magic_ip, Ipv4Addr::new(100, 100, 100, 53));
        // Must run BEFORE the osdns overlay is installed; afterwards the OS
        // state points at PeerDNS and only the explicit snapshot is safe.
        let pinned = with_underlay_upstream(&dns);
        match parse_upstream(&pinned.upstream).unwrap() {
            UpstreamSource::System => {
                // Host without system DNS: `build_resolver` fails closed.
            }
            UpstreamSource::Config(config) => {
                assert!(!config.name_servers.is_empty());
                assert!(
                    config
                        .name_servers
                        .iter()
                        .all(|ns| ns.ip != std::net::IpAddr::V4(dns.magic_ip)),
                    "Hickory must never use PeerDNS as its own upstream"
                );
            }
        }
    }

    #[test]
    fn system_conf_path_is_callable() {
        let _ = hickory_resolver::system_conf::read_system_conf();
        match parse_upstream(&["system".into()]).unwrap() {
            UpstreamSource::System => {}
            UpstreamSource::Config(_) => panic!("system"),
        }
    }

    #[tokio::test]
    async fn custom_port_failover_tcp_and_cache() {
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let (udp_addr, tcp_addr) = spawn_test_servers(udp_hits.clone(), tcp_hits.clone()).await;

        let dns = DnsConfig {
            suffix: "tunnet".into(),
            upstream: vec![
                format!("udp://{}:{}", udp_addr.ip(), udp_addr.port()),
                format!("tcp://{}:{}", tcp_addr.ip(), tcp_addr.port()),
            ],
            dnssec: false,
            ..DnsConfig::default()
        };
        let parsed = match parse_upstream(&dns.upstream).unwrap() {
            UpstreamSource::Config(c) => c,
            UpstreamSource::System => panic!("config"),
        };
        let ports: Vec<u16> = parsed
            .name_servers
            .iter()
            .flat_map(connection_summary)
            .map(|(_, p)| p)
            .collect();
        assert!(ports.contains(&udp_addr.port()));
        assert!(ports.contains(&tcp_addr.port()));

        let hickory = HickoryLookup::from_dns_config(&dns).unwrap();
        let table = routes();
        let mesh = process_query(
            &query_bytes("desktop.tunnet.", RecordType::A, 11),
            &table,
            "tunnet",
            &hickory,
        )
        .await;
        let mesh_msg = Message::from_bytes(&mesh).unwrap();
        assert!(mesh_msg.metadata.authoritative);
        assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
        assert_eq!(tcp_hits.load(Ordering::SeqCst), 0);

        let first = hickory
            .lookup(Name::from_str("ok.example.").unwrap(), RecordType::A)
            .await;
        match first {
            ExternalAnswer::Records(_) | ExternalAnswer::NoData | ExternalAnswer::NxDomain => {}
            ExternalAnswer::ServFail => {
                assert!(
                    udp_hits.load(Ordering::SeqCst) + tcp_hits.load(Ordering::SeqCst) > 0,
                    "resolver should have contacted the test nameserver"
                );
            }
        }

        let before = udp_hits.load(Ordering::SeqCst) + tcp_hits.load(Ordering::SeqCst);
        let _ = hickory
            .lookup(Name::from_str("ok.example.").unwrap(), RecordType::A)
            .await;
        let after = udp_hits.load(Ordering::SeqCst) + tcp_hits.load(Ordering::SeqCst);
        assert!(
            after <= before + 1,
            "second lookup should mostly hit cache, hits {before} -> {after}"
        );
    }

    async fn spawn_test_servers(
        udp_hits: Arc<AtomicUsize>,
        tcp_hits: Arc<AtomicUsize>,
    ) -> (SocketAddr, SocketAddr) {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                udp_hits.fetch_add(1, Ordering::SeqCst);
                if let Ok(req) = Message::from_bytes(&buf[..n]) {
                    let mut resp = Message::response(req.metadata.id, OpCode::Query);
                    resp.queries = req.queries.clone();
                    resp.metadata.truncation = true;
                    resp.metadata.recursion_available = true;
                    if let Ok(bytes) = resp.to_bytes() {
                        let _ = udp.send_to(&bytes, peer).await;
                    }
                }
            }
        });

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    break;
                };
                tcp_hits.fetch_add(1, Ordering::SeqCst);
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut lenb = [0u8; 2];
                if stream.read_exact(&mut lenb).await.is_err() {
                    continue;
                }
                let len = u16::from_be_bytes(lenb) as usize;
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    continue;
                }
                let Ok(req) = Message::from_bytes(&body) else {
                    continue;
                };
                let mut resp = Message::response(req.metadata.id, OpCode::Query);
                resp.queries = req.queries.clone();
                resp.metadata.recursion_available = true;
                if let Some(q) = req.queries.first() {
                    resp.add_answer(Record::from_rdata(
                        q.name.clone(),
                        30,
                        RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
                    ));
                }
                if let Ok(out) = resp.to_bytes() {
                    let n = (out.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&n).await;
                    let _ = stream.write_all(&out).await;
                }
            }
        });
        (udp_addr, tcp_addr)
    }
}
