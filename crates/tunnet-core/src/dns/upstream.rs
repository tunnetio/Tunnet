//! Shared Hickory resolver for names Tunnet does not own.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_resolver::config::{
    ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
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

pub struct HickoryLookup {
    resolver: TokioResolver,
}

impl HickoryLookup {
    pub fn from_dns_config(dns: &DnsConfig) -> anyhow::Result<Self> {
        Ok(Self {
            resolver: build_resolver(dns)?,
        })
    }
}

impl ExternalLookup for HickoryLookup {
    fn lookup(&self, name: Name, qtype: RecordType) -> ExtLookupFut<'_> {
        Box::pin(async move {
            match self.resolver.lookup(name, qtype).await {
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
/// itself (host-local loopback endpoint).
///
/// This is the second line of defense against DNS loops. The primary
/// invariant is ordering: the agent captures the underlay upstream
/// *before* installing the osdns overlay that points the OS at PeerDNS
/// (see `capture_underlay_upstream_specs`). Even if a resolver is (re)built
/// after the overlay is live, filtering guarantees Hickory never selects
/// PeerDNS as its own upstream merely because system DNS changed.
pub fn local_resolver_ip() -> Ipv4Addr {
    tunnet_common::LocalResolverEndpoint::default().ip
}

pub fn system_nameservers_excluding(resolver_ip: Ipv4Addr) -> Vec<IpAddr> {
    let Ok((conf, _)) = hickory_resolver::system_conf::read_system_conf() else {
        return Vec::new();
    };
    filter_self_nameservers(conf.name_servers.iter().map(|ns| ns.ip), resolver_ip)
}

/// Pure filter used by [`system_nameservers_excluding`] and unit-tested
/// directly: drop PeerDNS's own address so a post-overlay system state can
/// never become our upstream.
pub fn filter_self_nameservers(
    candidates: impl IntoIterator<Item = IpAddr>,
    resolver_ip: Ipv4Addr,
) -> Vec<IpAddr> {
    let excluded = IpAddr::V4(resolver_ip);
    let mut out = Vec::new();
    for ip in candidates {
        if ip == excluded || out.contains(&ip) {
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
pub fn capture_underlay_upstream_specs(resolver_ip: Ipv4Addr) -> Vec<String> {
    system_nameservers_excluding(resolver_ip)
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
    let captured = capture_underlay_upstream_specs(local_resolver_ip());
    if captured.is_empty() {
        return dns.clone();
    }
    DnsConfig {
        upstream: captured,
        ..dns.clone()
    }
}

pub fn build_resolver(dns: &DnsConfig) -> anyhow::Result<TokioResolver> {
    ensure_rustls();
    let resolver_ip = local_resolver_ip();
    match parse_upstream(&dns.upstream)? {
        UpstreamSource::System => {
            // Never resolve through ourselves: the OS state may already point
            // at PeerDNS if this runs after the overlay was applied
            // (or after roaming re-pointed the stub at us).
            let (conf, _) = hickory_resolver::system_conf::read_system_conf()
                .map_err(|e| anyhow::anyhow!("system DNS configuration: {e}"))?;
            let filtered =
                filter_self_nameservers(conf.name_servers.iter().map(|ns| ns.ip), resolver_ip);
            if filtered.is_empty() {
                anyhow::bail!(
                    "system DNS points only at PeerDNS ({}); refusing to create \
                     a recursive upstream loop. Configure an explicit upstream \
                     or capture the underlay resolver before installing the OS overlay",
                    resolver_ip
                );
            }
            let explicit = ResolverConfig::from_parts(
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
            );
            let mut builder =
                Resolver::builder_with_config(explicit, TokioRuntimeProvider::default());
            apply_tunnet_opts(builder.options_mut(), dns.dnssec);
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("build system resolver: {e}"))
        }
        UpstreamSource::Config(config) => {
            let mut builder =
                Resolver::builder_with_config(config, TokioRuntimeProvider::default());
            apply_tunnet_opts(builder.options_mut(), dns.dnssec);
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("build resolver: {e}"))
        }
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
    if err.is_no_records_found() {
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
