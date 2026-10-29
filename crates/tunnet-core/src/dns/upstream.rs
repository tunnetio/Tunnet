//! Shared Hickory resolver for names Tunnet does not own.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use std::net::{IpAddr, Ipv4Addr};

use super::runtime::NativeHickoryRuntimeProvider;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::NetError;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tunnet_common::DnsConfig;

use super::nameserver::{UpstreamSource, parse_upstream};

pub enum ExternalAnswer {
    Records(Vec<Record>),
    NxDomain,
    NoData,
    ServFail,
}

pub type ExtLookupFut<'a> = Pin<Box<dyn Future<Output = ExternalAnswer> + Send + 'a>>;

pub trait ExternalLookup: Send + Sync {
    fn lookup(&self, name: Name, qtype: RecordType) -> ExtLookupFut<'_>;
}

type NativeResolver = Resolver<NativeHickoryRuntimeProvider>;

#[derive(Debug)]
struct Generation {
    resolver: NativeResolver,
    fallback: Option<NativeResolver>,
    retired: CancellationToken,
}

#[derive(Debug)]
pub struct HickoryLookup {
    config: ResolverConfig,
    fallback_config: Option<ResolverConfig>,
    upstream: Vec<String>,
    system: Option<ResolverConfig>,
    options: ResolverOpts,
    runtime: NativeHickoryRuntimeProvider,
    tls: rustls::ClientConfig,
    hosts: Arc<hickory_resolver::Hosts>,
    current: Mutex<Arc<Generation>>,
}

impl HickoryLookup {
    /// Capture Iroh's system tier before PeerDNS changes OS DNS. Public DNS is
    /// a separate, protected tier and is never queried for a terminal answer.
    pub fn with_system_runtime(runtime: NativeHickoryRuntimeProvider) -> anyhow::Result<Self> {
        ensure_rustls();
        let system =
            hickory_resolver::system_conf::read_system_conf()
                .ok()
                .map(|(mut config, options)| {
                    let excluded = tunnet_common::resolver_self_ips();
                    config
                        .name_servers
                        .retain(|server| !excluded.iter().any(|ip| IpAddr::V4(*ip) == server.ip));
                    (config, options)
                });
        Self::with_captured_system(system, public_fallback_config()?, runtime)
    }

    fn with_captured_system(
        system: Option<(ResolverConfig, ResolverOpts)>,
        fallback: ResolverConfig,
        runtime: NativeHickoryRuntimeProvider,
    ) -> anyhow::Result<Self> {
        ensure_rustls();
        let system = system.filter(|(config, _)| !config.name_servers.is_empty());
        let (config, options) = system
            .clone()
            .unwrap_or_else(|| (fallback.clone(), ResolverOpts::default()));
        let mut owner = Self::from_parts(
            config,
            Vec::new(),
            system.map(|(config, _)| config),
            options,
            runtime,
            hickory_resolver::net::tls::client_config()?,
            Arc::new(hickory_resolver::Hosts::from_system().unwrap_or_default()),
        )?;
        if owner.system.is_some() {
            owner.fallback_config = Some(fallback);
            owner.reset();
        }
        Ok(owner)
    }

    pub fn from_dns_config(dns: &DnsConfig) -> anyhow::Result<Self> {
        Self::with_runtime(dns, NativeHickoryRuntimeProvider::default())
    }

    pub fn with_runtime(
        dns: &DnsConfig,
        runtime: NativeHickoryRuntimeProvider,
    ) -> anyhow::Result<Self> {
        ensure_rustls();
        let config = resolver_config(dns)?;
        let system = if matches!(parse_upstream(&dns.upstream)?, UpstreamSource::System) {
            Some(config.clone())
        } else {
            resolver_config(&DnsConfig {
                upstream: vec!["system".into()],
                ..DnsConfig::default()
            })
            .ok()
        };
        let options = tunnet_resolver_opts(dns.dnssec);
        let tls = hickory_resolver::net::tls::client_config()?;
        Self::from_parts(
            config,
            dns.upstream.clone(),
            system,
            options,
            runtime,
            tls,
            Arc::new(hickory_resolver::Hosts::from_system().unwrap_or_default()),
        )
    }

    pub fn for_dns_config(self: &Arc<Self>, dns: &DnsConfig) -> anyhow::Result<Arc<Self>> {
        if self.fallback_config.is_none()
            && !self.upstream.is_empty()
            && self.upstream == dns.upstream
            && self.options.validate == dns.dnssec
        {
            return Ok(self.clone());
        }
        let config = match parse_upstream(&dns.upstream)? {
            UpstreamSource::System => self
                .system
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no captured pre-overlay system DNS servers"))?,
            UpstreamSource::Config(config) => config,
        };
        Self::from_parts(
            config,
            dns.upstream.clone(),
            self.system.clone(),
            tunnet_resolver_opts(dns.dnssec),
            self.runtime.clone(),
            self.tls.clone(),
            self.hosts.clone(),
        )
        .map(Arc::new)
    }

    fn from_parts(
        config: ResolverConfig,
        upstream: Vec<String>,
        system: Option<ResolverConfig>,
        options: ResolverOpts,
        runtime: NativeHickoryRuntimeProvider,
        tls: rustls::ClientConfig,
        hosts: Arc<hickory_resolver::Hosts>,
    ) -> anyhow::Result<Self> {
        let resolver = native_resolver(
            config.clone(),
            options.clone(),
            runtime.clone(),
            tls.clone(),
            hosts.clone(),
        )?;
        Ok(Self {
            config,
            fallback_config: None,
            upstream,
            system,
            options,
            runtime,
            tls,
            hosts,
            current: Mutex::new(Arc::new(Generation {
                resolver,
                fallback: None,
                retired: CancellationToken::new(),
            })),
        })
    }

    pub(crate) async fn records(
        &self,
        name: impl hickory_proto::rr::IntoName,
        qtype: RecordType,
    ) -> Result<hickory_resolver::lookup::Lookup, NetError> {
        let name = name.into_name()?;
        let generation = self.current.lock().clone();
        tokio::select! {
            biased;
            _ = generation.retired.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "DNS generation retired").into()),
            answer = async {
                match generation.resolver.lookup(name.clone(), qtype).await {
                    Err(error) if !error.is_nx_domain() && !is_nodata(&error) => {
                        match &generation.fallback {
                            Some(fallback) => fallback.lookup(name, qtype).await,
                            None => Err(error),
                        }
                    }
                    answer => answer,
                }
            } => answer,
        }
    }

    pub fn clear_cache(&self) {
        let current = self.current.lock();
        current.resolver.clear_cache();
        if let Some(fallback) = &current.fallback {
            fallback.clear_cache();
        }
    }

    pub fn reset(&self) {
        let resolver = native_resolver(
            self.config.clone(),
            self.options.clone(),
            self.runtime.clone(),
            self.tls.clone(),
            self.hosts.clone(),
        )
        .expect("validated DNS configuration must remain buildable without I/O");
        let fallback = self.fallback_config.as_ref().map(|config| {
            native_resolver(
                config.clone(),
                self.options.clone(),
                self.runtime.clone(),
                self.tls.clone(),
                self.hosts.clone(),
            )
            .expect("retained fallback configuration must remain buildable without I/O")
        });
        let mut current = self.current.lock();
        current.retired.cancel();
        *current = Arc::new(Generation {
            resolver,
            fallback,
            retired: CancellationToken::new(),
        });
    }
}

pub(super) fn is_nodata(error: &NetError) -> bool {
    matches!(error, NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(records)) if records.response_code == ResponseCode::NoError)
}

fn public_fallback_config() -> anyhow::Result<ResolverConfig> {
    // n0-dns-resolver 0.1.0 public_resolvers::default_order, with UDP's TCP retry.
    let specs = [
        "udp+tcp://1.1.1.1",
        "udp+tcp://8.8.8.8",
        "https://1.1.1.1#1.1.1.1",
        "https://8.8.8.8#8.8.8.8",
        "https://9.9.9.9#9.9.9.9",
        "udp+tcp://9.9.9.9",
        "udp+tcp://[2606:4700:4700::1111]",
        "udp+tcp://[2001:4860:4860::8888]",
        "udp+tcp://[2620:fe::fe]",
        "udp+tcp://1.0.0.1",
        "udp+tcp://8.8.4.4",
        "udp+tcp://149.112.112.112",
        "udp+tcp://[2606:4700:4700::1001]",
        "udp+tcp://[2001:4860:4860::8844]",
        "udp+tcp://[2620:fe::9]",
    ]
    .map(String::from);
    let mut servers = Vec::new();
    for spec in specs {
        let UpstreamSource::Config(config) = parse_upstream(&[spec])? else {
            unreachable!()
        };
        servers.extend(config.name_servers);
    }
    Ok(ResolverConfig::from_parts(None, Vec::new(), servers))
}

fn native_resolver(
    config: ResolverConfig,
    mut options: ResolverOpts,
    runtime: NativeHickoryRuntimeProvider,
    tls: rustls::ClientConfig,
    hosts: Arc<hickory_resolver::Hosts>,
) -> anyhow::Result<NativeResolver> {
    let mut builder = Resolver::builder_with_config(config, runtime.fresh()).with_tls_config(tls);
    options.use_hosts_file = ResolveHosts::Never;
    *builder.options_mut() = options;
    let mut resolver = builder
        .build()
        .map_err(|err| anyhow::anyhow!("build resolver: {err}"))?;
    resolver.set_hosts(hosts);
    Ok(resolver)
}

impl ExternalLookup for HickoryLookup {
    fn lookup(&self, name: Name, qtype: RecordType) -> ExtLookupFut<'_> {
        Box::pin(async move {
            match self.records(name, qtype).await {
                Ok(lookup) => {
                    let msg = lookup.message();
                    let mut records = Vec::new();
                    records.extend(msg.answers.iter().cloned());
                    records.extend(msg.authorities.iter().cloned());
                    records.extend(msg.additionals.iter().cloned());
                    if records.is_empty() {
                        ExternalAnswer::NoData
                    } else {
                        ExternalAnswer::Records(records)
                    }
                }
                Err(err) => map_resolve_error(&err),
            }
        })
    }
}

fn ensure_rustls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Read the OS resolver list, dropping any entry that points at PeerDNS
/// itself (loopback listener or in-TUN virtual address).
///
/// This is the second line of defense against DNS loops. The primary
/// invariant is ordering: the agent captures the underlay upstream
/// *before* installing the osdns overlay that points the OS at PeerDNS
/// (see `capture_underlay_upstream_specs`). Even if a resolver is (re)built
/// after the overlay is live, filtering guarantees Hickory never selects
/// PeerDNS as its own upstream merely because system DNS changed.
pub fn system_nameservers_excluding(excluded: impl IntoIterator<Item = Ipv4Addr>) -> Vec<IpAddr> {
    let Ok((conf, _)) = hickory_resolver::system_conf::read_system_conf() else {
        return Vec::new();
    };
    filter_self_nameservers(conf.name_servers.iter().map(|ns| ns.ip), excluded)
}

/// Pure filter used by [`system_nameservers_excluding`] and unit-tested
/// directly: drop PeerDNS's own addresses so a post-overlay system state can
/// never become our upstream.
pub fn filter_self_nameservers(
    candidates: impl IntoIterator<Item = IpAddr>,
    excluded: impl IntoIterator<Item = Ipv4Addr>,
) -> Vec<IpAddr> {
    let excluded: Vec<IpAddr> = excluded.into_iter().map(IpAddr::V4).collect();
    let mut out = Vec::new();
    for ip in candidates {
        if excluded.contains(&ip) || out.contains(&ip) {
            continue;
        }
        out.push(ip);
    }
    out
}

/// Snapshot the current (pre-overlay) system upstreams as explicit
/// `udp+tcp://ip:53` specs, excluding PeerDNS itself.
///
/// Returns an empty vec when the system exposes no usable upstream; callers
/// should then fail safely instead of falling back to a recursive `"system"`
/// read performed after the overlay is installed.
pub fn capture_underlay_upstream_specs(
    excluded: impl IntoIterator<Item = Ipv4Addr>,
) -> Vec<String> {
    system_nameservers_excluding(excluded)
        .into_iter()
        .map(|ip| format!("udp+tcp://{ip}:53"))
        .collect()
}

/// Rewrite a `"system"` upstream into the explicit underlay snapshot taken
/// before the osdns overlay is applied.
///
/// Must be called *before* installing the overlay; after the overlay the OS
/// state points at PeerDNS and a fresh `"system"` read would loop. When no
/// underlay servers are visible the config is returned unchanged and
/// [`build_resolver`] will refuse to build a looping resolver.
pub fn with_underlay_upstream(dns: &DnsConfig) -> DnsConfig {
    let wants_system = dns
        .upstream
        .iter()
        .any(|s| s.trim().eq_ignore_ascii_case("system"));
    if !wants_system {
        return dns.clone();
    }
    let captured = capture_underlay_upstream_specs(tunnet_common::resolver_self_ips());
    if captured.is_empty() {
        return dns.clone();
    }
    DnsConfig {
        upstream: captured,
        ..dns.clone()
    }
}

pub fn build_resolver(dns: &DnsConfig) -> anyhow::Result<NativeResolver> {
    ensure_rustls();
    native_resolver(
        resolver_config(dns)?,
        tunnet_resolver_opts(dns.dnssec),
        NativeHickoryRuntimeProvider::default(),
        hickory_resolver::net::tls::client_config()?,
        Arc::new(hickory_resolver::Hosts::from_system().unwrap_or_default()),
    )
}

fn resolver_config(dns: &DnsConfig) -> anyhow::Result<ResolverConfig> {
    match parse_upstream(&dns.upstream)? {
        UpstreamSource::System => {
            let (conf, _) = hickory_resolver::system_conf::read_system_conf()
                .map_err(|e| anyhow::anyhow!("system DNS configuration: {e}"))?;
            let filtered = filter_self_nameservers(
                conf.name_servers.iter().map(|ns| ns.ip),
                tunnet_common::resolver_self_ips(),
            );
            anyhow::ensure!(
                !filtered.is_empty(),
                "no usable pre-overlay system DNS servers"
            );
            Ok(ResolverConfig::from_parts(
                conf.domain().cloned(),
                conf.search().to_vec(),
                filtered
                    .into_iter()
                    .map(|ip| {
                        use hickory_resolver::config::{ConnectionConfig, NameServerConfig};
                        NameServerConfig::new(
                            ip,
                            true,
                            vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
                        )
                    })
                    .collect(),
            ))
        }
        UpstreamSource::Config(config) => Ok(config),
    }
}

/// Options Hickory should use for the local stub proxy.
///
/// DNSSEC `validate` follows `DnsConfig.dnssec`. Hickory itself defaults to
/// off; we keep that unless the operator opts in, because a validating stub
/// in front of a non-validating forwarder (or a broken middlebox) SERVFAILs
/// signed zones that would otherwise resolve.
pub fn tunnet_resolver_opts(dnssec: bool) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    apply_tunnet_opts(&mut opts, dnssec);
    opts
}

fn apply_tunnet_opts(opts: &mut ResolverOpts, dnssec: bool) {
    opts.edns0 = true;
    opts.try_tcp_on_error = true;
    opts.preserve_intermediates = true;
    opts.recursion_desired = true;
    opts.num_concurrent_reqs = 2;
    opts.max_active_requests = 32;
    opts.cache_size = 32;
    opts.attempts = 2;
    opts.timeout = Duration::from_secs(5);
    opts.use_hosts_file = ResolveHosts::Auto;
    opts.server_ordering_strategy = ServerOrderingStrategy::QueryStatistics;
    opts.validate = dnssec;
}

fn map_resolve_error(err: &NetError) -> ExternalAnswer {
    if err.is_nx_domain() {
        return ExternalAnswer::NxDomain;
    }
    if is_nodata(err) {
        return ExternalAnswer::NoData;
    }
    tracing::debug!(error = %err, "hickory lookup failed");
    ExternalAnswer::ServFail
}

pub fn map_external(answer: ExternalAnswer) -> (ResponseCode, Vec<Record>) {
    match answer {
        ExternalAnswer::Records(records) => (ResponseCode::NoError, records),
        ExternalAnswer::NxDomain => (ResponseCode::NXDomain, Vec::new()),
        ExternalAnswer::NoData => (ResponseCode::NoError, Vec::new()),
        ExternalAnswer::ServFail => (ResponseCode::ServFail, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        NativeHickoryRuntimeProvider,
        iroh::{IrohResolver, error},
    };
    use hickory_resolver::net::runtime::RuntimeProvider;
    use iroh::dns::DnsError;
    use iroh::dns::DnsResolver;
    use rstest::rstest;
    use std::{
        io,
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{
        net::{TcpListener, UdpSocket},
        time::timeout,
    };
    use tunnet_common::DnsConfig;

    static DENIED: AtomicUsize = AtomicUsize::new(0);
    fn deny_udp(_: &std::net::UdpSocket) -> io::Result<()> {
        DENIED.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn deny_tcp(_: &std::net::TcpStream) -> io::Result<()> {
        DENIED.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::PermissionDenied.into())
    }
    static REVOKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn revocable_udp(socket: &std::net::UdpSocket) -> io::Result<()> {
        if REVOKED.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        ttl_udp(socket)
    }
    fn revocable_tcp(socket: &std::net::TcpStream) -> io::Result<()> {
        if REVOKED.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        ttl_tcp(socket)
    }
    fn ttl_udp(socket: &std::net::UdpSocket) -> io::Result<()> {
        socket.set_ttl(42)
    }
    fn ttl_tcp(socket: &std::net::TcpStream) -> io::Result<()> {
        socket.set_ttl(42)
    }
    fn ttl6_udp(socket: &std::net::UdpSocket) -> io::Result<()> {
        socket2::SockRef::from(socket).set_unicast_hops_v6(42)
    }
    fn ttl6_tcp(socket: &std::net::TcpStream) -> io::Result<()> {
        socket2::SockRef::from(socket).set_unicast_hops_v6(42)
    }
    fn runtime(deny: bool) -> NativeHickoryRuntimeProvider {
        NativeHickoryRuntimeProvider::new(
            [
                ttl_udp as fn(&std::net::UdpSocket) -> io::Result<()>,
                ttl6_udp,
            ]
            .map(|allow| {
                Some(netwatch::SocketConfig {
                    interface: None,
                    initialize: Some(if deny { deny_udp } else { allow }),
                })
            }),
            [
                ttl_tcp as fn(&std::net::TcpStream) -> io::Result<()>,
                ttl6_tcp,
            ]
            .map(|allow| {
                Some(netwatch::TcpSocketConfig {
                    interface: None,
                    initialize: Some(if deny { deny_tcp } else { allow }),
                })
            }),
        )
    }

    fn service(spec: String, runtime: NativeHickoryRuntimeProvider) -> Arc<HickoryLookup> {
        let config = DnsConfig {
            upstream: vec![spec],
            ..DnsConfig::default()
        };
        let mut lookup = HickoryLookup::with_runtime(&config, runtime).unwrap();
        lookup.options.timeout = Duration::from_millis(100);
        lookup.options.attempts = 1;
        lookup.reset();
        Arc::new(lookup)
    }

    #[tokio::test]
    async fn deferred_fallback_waits_for_primary_timeout() {
        use hickory_proto::{
            op::Message,
            rr::{RData, rdata::A},
            serialize::binary::{BinDecodable, BinEncodable},
        };
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut owner = Arc::try_unwrap(service(
            format!("udp://{}", primary.local_addr().unwrap()),
            runtime(false),
        ))
        .unwrap();
        let UpstreamSource::Config(config) =
            parse_upstream(&[format!("udp://{}", fallback.local_addr().unwrap())]).unwrap()
        else {
            unreachable!()
        };
        owner.fallback_config = Some(config);
        owner.reset();
        let owner = Arc::new(owner);
        let lookup =
            tokio::spawn(async move { owner.records("private.example.", RecordType::A).await });
        let mut bytes = [0; 2048];
        timeout(Duration::from_secs(1), primary.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(20), fallback.recv_from(&mut bytes))
                .await
                .is_err()
        );
        let (len, peer) = timeout(Duration::from_secs(2), fallback.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let query = Message::from_bytes(&bytes[..len]).unwrap();
        let question = query.queries[0].clone();
        let mut response = Message::response(query.id, query.op_code);
        response.metadata.recursion_available = true;
        response.add_query(question.clone());
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            60,
            RData::A(A("192.0.2.19".parse().unwrap())),
        ));
        fallback
            .send_to(&response.to_bytes().unwrap(), peer)
            .await
            .unwrap();
        let answer = lookup.await.unwrap().unwrap();
        assert_eq!(
            answer.message().answers[0].data,
            RData::A(A("192.0.2.19".parse().unwrap()))
        );
    }

    #[test]
    fn only_noerror_no_records_is_empty_success() {
        use hickory_resolver::net::{DnsError, NoRecords};
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::FormErr,
            ResponseCode::NXDomain,
        ] {
            let error = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
                hickory_proto::op::Query::default(),
                code,
            )));
            assert!(!is_nodata(&error));
            assert!(matches!(
                map_resolve_error(&error),
                ExternalAnswer::ServFail | ExternalAnswer::NxDomain
            ));
        }
        let error = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            hickory_proto::op::Query::default(),
            ResponseCode::NoError,
        )));
        assert!(is_nodata(&error));
    }

    #[rstest]
    #[case(ResponseCode::NoError, true, false, true)]
    #[case(ResponseCode::NoError, false, false, true)]
    #[case(ResponseCode::NXDomain, false, false, true)]
    #[case(ResponseCode::ServFail, false, true, true)]
    #[case(ResponseCode::Refused, false, true, true)]
    #[case(ResponseCode::NoError, false, true, false)]
    #[tokio::test]
    async fn deferred_tiers_retain_servers_cache_and_authority(
        #[case] code: ResponseCode,
        #[case] has_answer: bool,
        #[case] uses_fallback: bool,
        #[case] primary_present: bool,
    ) {
        use hickory_proto::{
            op::Message,
            rr::{RData, rdata::A},
            serialize::binary::{BinDecodable, BinEncodable},
        };
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_address = primary.local_addr().unwrap();
        let fallback_address = fallback.local_addr().unwrap();
        let UpstreamSource::Config(primary_config) =
            parse_upstream(&[format!("udp://{primary_address}")]).unwrap()
        else {
            unreachable!()
        };
        let UpstreamSource::Config(fallback_config) =
            parse_upstream(&[format!("udp://{fallback_address}")]).unwrap()
        else {
            unreachable!()
        };
        let owner = HickoryLookup::with_captured_system(
            primary_present.then(|| (primary_config, tunnet_resolver_opts(false))),
            fallback_config.clone(),
            runtime(false),
        )
        .unwrap();
        let owner = Arc::new(owner);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for (socket, is_fallback) in [(primary, false), (fallback, true)] {
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                let mut bytes = [0; 2048];
                loop {
                    let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
                    if is_fallback {
                        calls.fetch_add(1, Ordering::SeqCst);
                    }
                    let query = Message::from_bytes(&bytes[..len]).unwrap();
                    let question = query.queries[0].clone();
                    let mut response = Message::response(query.id, query.op_code);
                    response.metadata.recursion_available = true;
                    response.metadata.response_code = if is_fallback {
                        ResponseCode::NoError
                    } else {
                        code
                    };
                    response.add_query(question.clone());
                    if is_fallback || has_answer {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::A(A("192.0.2.17".parse().unwrap())),
                        ));
                    }
                    socket
                        .send_to(&response.to_bytes().unwrap(), peer)
                        .await
                        .unwrap();
                }
            }));
        }
        let dns = DnsResolver::custom(IrohResolver(owner.clone()));
        for round in 0..3 {
            if round == 1 {
                dns.clear_cache();
            }
            if round == 2 {
                dns.reset();
            }
            let answer = dns
                .lookup_ipv4("private.example.", Duration::from_secs(2))
                .await;
            if code == ResponseCode::NXDomain {
                assert!(matches!(answer, Err(DnsError::NxDomain { .. })));
            } else {
                assert_eq!(
                    answer.unwrap().collect::<Vec<_>>(),
                    if has_answer || uses_fallback {
                        vec!["192.0.2.17".parse::<IpAddr>().unwrap()]
                    } else {
                        Vec::new()
                    }
                );
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if uses_fallback { round + 1 } else { 0 }
            );
        }
        // Reset must retain both tiers' fail-closed native socket authority.
        let before = DENIED.load(Ordering::SeqCst);
        let mut denied =
            Arc::try_unwrap(service(format!("udp://{primary_address}"), runtime(true))).unwrap();
        denied.fallback_config = Some(fallback_config.clone());
        denied.reset();
        for _ in 0..2 {
            assert!(
                denied
                    .records("denied.example.", RecordType::A)
                    .await
                    .is_err()
            );
            denied.reset();
        }
        assert!(DENIED.load(Ordering::SeqCst) >= before + 4);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if uses_fallback { 3 } else { 0 }
        );
        let mut missing = Arc::try_unwrap(service(
            format!("udp://{primary_address}"),
            NativeHickoryRuntimeProvider::new([None; 2], [None; 2]),
        ))
        .unwrap();
        missing.fallback_config = Some(fallback_config);
        missing.reset();
        assert!(
            missing
                .records("missing.example.", RecordType::A)
                .await
                .is_err()
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if uses_fallback { 3 } else { 0 }
        );
        for task in tasks {
            task.abort();
        }
    }

    async fn dns_listeners() -> (TcpListener, UdpSocket) {
        for _ in 0..32 {
            let address = (
                std::net::Ipv4Addr::LOCALHOST,
                rand::random_range(1024..49152),
            );
            let tcp = match TcpListener::bind(address).await {
                Ok(tcp) => tcp,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("DNS TCP listener: {error}"),
            };
            match UdpSocket::bind(address).await {
                Ok(udp) => return (tcp, udp),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) => {}
                Err(error) => panic!("DNS UDP listener: {error}"),
            }
        }
        panic!("no jointly available DNS TCP/UDP port");
    }

    #[rstest]
    #[case("udp")]
    #[case("tcp")]
    #[case("tls")]
    #[case("https")]
    #[tokio::test]
    async fn transport_denial_has_no_fallback_across_iroh_reset(#[case] scheme: &str) {
        let (tcp, udp) = dns_listeners().await;
        let address = tcp.local_addr().unwrap();
        let before = DENIED.load(Ordering::SeqCst);
        let lookup = service(format!("{scheme}://{address}#localhost"), runtime(true));
        let dns = DnsResolver::custom(IrohResolver(lookup.clone()));
        for _ in 0..2 {
            assert!(
                dns.lookup_ipv4("denied.example.", Duration::from_secs(2))
                    .await
                    .is_err()
            );
            dns.reset();
        }
        assert!(DENIED.load(Ordering::SeqCst) >= before + 2);
        assert!(
            timeout(Duration::from_millis(20), tcp.accept())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(20), udp.recv_from(&mut [0; 512]))
                .await
                .is_err()
        );
        let missing = NativeHickoryRuntimeProvider::new([None; 2], [None; 2]);
        let missing_dns = DnsResolver::custom(IrohResolver(service(
            format!("{scheme}://{address}#localhost"),
            missing,
        )));
        assert!(
            missing_dns
                .lookup_ipv4("denied.example.", Duration::from_secs(2))
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(20), tcp.accept())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(20), udp.recv_from(&mut [0; 512]))
                .await
                .is_err()
        );
    }
    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn native_provider_preserves_source_family_and_callback(#[case] address: SocketAddr) {
        let listener = TcpListener::bind(address).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let provider = runtime(false);
        let stream = provider
            .connect_tcp(destination, Some(address), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), address.ip());
        assert_eq!(
            if address.is_ipv6() {
                socket2::SockRef::from(&stream.0).unicast_hops_v6().unwrap()
            } else {
                stream.0.ttl().unwrap()
            },
            42
        );
        let udp = provider.bind_udp(address, destination).await.unwrap();
        assert_eq!(udp.local_addr().unwrap().ip(), address.ip());
        assert_eq!(
            if address.is_ipv6() {
                socket2::SockRef::from(&udp).unicast_hops_v6().unwrap()
            } else {
                udp.ttl().unwrap()
            },
            42
        );
        let missing = NativeHickoryRuntimeProvider::new([None; 2], [None; 2]);
        assert_eq!(
            missing
                .connect_tcp(destination, None, None)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            missing
                .bind_udp(address, destination)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn adapter_answers_cache_reset_and_truncation() {
        use hickory_proto::{
            op::{Message, MessageType, ResponseCode},
            rr::{
                RData, Record,
                rdata::{A, AAAA, TXT},
            },
            serialize::binary::{BinDecodable, BinEncodable},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        timeout(Duration::from_secs(8), async {
            let (tcp, udp) = dns_listeners().await;
            let address = tcp.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let received = calls.clone();
            let (hold, mut held) = tokio::sync::mpsc::channel(1);
            let (pool, mut pooled) = tokio::sync::mpsc::channel(1);
            let server = tokio::spawn(async move {
                let mut buf = [0; 4096];
                loop {
                    let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
                    let query = Message::from_bytes(&buf[..len]).unwrap();
                    let question = query.queries[0].clone();
                    let name = question.name().to_string();
                    received.fetch_add(1, Ordering::SeqCst);
                    if name == "held.example." {
                        hold.send(()).await.unwrap();
                        continue;
                    }
                    let mut answer = Message::response(query.id, query.op_code);
                    answer.metadata.message_type = MessageType::Response;
                    answer.metadata.recursion_available = true;
                    answer.add_query(question.clone());
                    if name == "nx.example." {
                        answer.metadata.response_code = ResponseCode::NXDomain;
                    } else if name == "servfail.example." {
                        answer.metadata.response_code = ResponseCode::ServFail;
                    } else if name != "empty.example." {
                        match question.query_type() {
                            RecordType::A => {
                                answer.add_answer(Record::from_rdata(
                                    question.name().clone(),
                                    60,
                                    RData::A(A("192.0.2.42".parse().unwrap())),
                                ));
                            }
                            RecordType::AAAA => {
                                answer.add_answer(Record::from_rdata(
                                    question.name().clone(),
                                    60,
                                    RData::AAAA(AAAA("2001:db8::42".parse().unwrap())),
                                ));
                            }
                            RecordType::TXT => {
                                for data in [vec![&b"a\0"[..], &b"\xffb"[..]], vec![&b"second"[..]]]
                                {
                                    answer.add_answer(Record::from_rdata(
                                        question.name().clone(),
                                        60,
                                        RData::TXT(TXT::from_bytes(data)),
                                    ));
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    if name == "fallback.example." {
                        let mut truncated = answer.clone();
                        truncated.answers.clear();
                        truncated.metadata.truncation = true;
                        udp.send_to(&truncated.to_bytes().unwrap(), peer)
                            .await
                            .unwrap();
                        let (mut stream, _) = tcp.accept().await.unwrap();
                        let len = stream.read_u16().await.unwrap();
                        let mut query = vec![0; len.into()];
                        stream.read_exact(&mut query).await.unwrap();
                        answer.metadata.id = Message::from_bytes(&query).unwrap().id;
                        let bytes = answer.to_bytes().unwrap();
                        stream
                            .write_u16(bytes.len().try_into().unwrap())
                            .await
                            .unwrap();
                        stream.write_all(&bytes).await.unwrap();
                        pool.send(stream).await.unwrap();
                    } else {
                        udp.send_to(&answer.to_bytes().unwrap(), peer)
                            .await
                            .unwrap();
                    }
                }
            });
            REVOKED.store(false, Ordering::SeqCst);
            let provider = NativeHickoryRuntimeProvider::new(
                [Some(netwatch::SocketConfig {
                    initialize: Some(revocable_udp),
                    ..Default::default()
                }); 2],
                [Some(netwatch::TcpSocketConfig {
                    initialize: Some(revocable_tcp),
                    ..Default::default()
                }); 2],
            );
            let service = service(format!("udp+tcp://{address}"), provider);
            let dns = DnsResolver::custom(IrohResolver(service.clone()));
            let wait = Duration::from_secs(2);
            assert_eq!(
                dns.lookup_ipv4("answer.example.", wait)
                    .await
                    .unwrap()
                    .collect::<Vec<_>>(),
                vec!["192.0.2.42".parse::<std::net::IpAddr>().unwrap()]
            );
            let before = calls.load(Ordering::SeqCst);
            assert_eq!(
                dns.lookup_ipv4("answer.example.", wait)
                    .await
                    .unwrap()
                    .count(),
                1
            );
            assert_eq!(calls.load(Ordering::SeqCst), before);
            dns.clear_cache();
            assert_eq!(
                dns.lookup_ipv4("answer.example.", wait)
                    .await
                    .unwrap()
                    .count(),
                1
            );
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
            dns.reset();
            assert_eq!(
                dns.lookup_ipv4("answer.example.", wait)
                    .await
                    .unwrap()
                    .count(),
                1
            );
            assert_eq!(calls.load(Ordering::SeqCst), before + 2);
            assert_eq!(
                dns.lookup_ipv6("answer.example.", wait)
                    .await
                    .unwrap()
                    .collect::<Vec<_>>(),
                vec!["2001:db8::42".parse::<std::net::IpAddr>().unwrap()]
            );
            let txt: Vec<Vec<Vec<u8>>> = dns
                .lookup_txt("answer.example.", wait)
                .await
                .unwrap()
                .map(|record| record.iter().map(<[u8]>::to_vec).collect())
                .collect();
            assert_eq!(
                txt,
                vec![
                    vec![b"a\0".to_vec(), b"\xffb".to_vec()],
                    vec![b"second".to_vec()]
                ]
            );
            assert!(matches!(
                dns.lookup_ipv4("nx.example.", wait).await,
                Err(DnsError::NxDomain { .. })
            ));
            assert_eq!(
                dns.lookup_ipv4("empty.example.", wait)
                    .await
                    .unwrap()
                    .count(),
                0
            );
            assert!(matches!(
                dns.lookup_ipv4("servfail.example.", wait).await,
                Err(DnsError::Resolve { .. })
            ));
            assert_eq!(
                dns.lookup_ipv4("fallback.example.", wait)
                    .await
                    .unwrap()
                    .collect::<Vec<_>>(),
                vec!["192.0.2.42".parse::<std::net::IpAddr>().unwrap()]
            );
            let mut pooled_stream = pooled.recv().await.unwrap();
            let old = service.current.lock().clone();
            let old_weak = Arc::downgrade(&old);
            drop(old);
            let pending = {
                let service = service.clone();
                tokio::spawn(async move { service.records("held.example.", RecordType::A).await })
            };
            held.recv().await.unwrap();
            REVOKED.store(true, Ordering::SeqCst);
            dns.reset();
            assert!(pending.await.unwrap().is_err());
            assert!(old_weak.upgrade().is_none());
            assert_eq!(
                timeout(Duration::from_secs(1), pooled_stream.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            let before = calls.load(Ordering::SeqCst);
            assert!(dns.lookup_ipv4("answer.example.", wait).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), before);
            assert!(matches!(error(NetError::Timeout), DnsError::Timeout { .. }));
            server.abort();
            let _ = server.await;
        })
        .await
        .unwrap();
    }
}
