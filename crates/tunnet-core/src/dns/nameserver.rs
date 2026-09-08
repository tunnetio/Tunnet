//! Parse Tunnet nameserver URLs into Hickory `NameServerConfig`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
#[cfg(test)]
use hickory_resolver::config::ProtocolConfig;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};

pub enum UpstreamSource {
    System,
    Config(ResolverConfig),
}

pub fn parse_upstream(specs: &[String]) -> anyhow::Result<UpstreamSource> {
    let trimmed: Vec<&str> = specs
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if trimmed.is_empty() {
        return parse_upstream(&tunnet_common::default_dns_upstream());
    }
    let system = trimmed.iter().any(|s| s.eq_ignore_ascii_case("system"));
    if system {
        if trimmed.len() != 1 {
            bail!("'system' cannot be mixed with explicit nameservers");
        }
        return Ok(UpstreamSource::System);
    }

    let mut by_ip: BTreeMap<IpAddr, Vec<ConnectionConfig>> = BTreeMap::new();
    let mut order: Vec<IpAddr> = Vec::new();
    for spec in trimmed {
        let (ip, connections) = parse_spec(spec)?;
        if !by_ip.contains_key(&ip) {
            order.push(ip);
        }
        by_ip.entry(ip).or_default().extend(connections);
    }

    let name_servers = order
        .into_iter()
        .map(|ip| NameServerConfig::new(ip, true, by_ip.remove(&ip).unwrap_or_default()))
        .collect();

    Ok(UpstreamSource::Config(ResolverConfig::from_parts(
        None,
        vec![],
        name_servers,
    )))
}

fn parse_spec(spec: &str) -> anyhow::Result<(IpAddr, Vec<ConnectionConfig>)> {
    if let Some((scheme, rest)) = spec.split_once("://") {
        return parse_url(scheme, rest).with_context(|| format!("nameserver {spec}"));
    }
    parse_plain(spec).with_context(|| format!("nameserver {spec}"))
}

fn parse_plain(spec: &str) -> anyhow::Result<(IpAddr, Vec<ConnectionConfig>)> {
    let (ip, port) = parse_ip_port(spec)?;
    let mut udp = ConnectionConfig::udp();
    let mut tcp = ConnectionConfig::tcp();
    if let Some(port) = port {
        udp.port = port;
        tcp.port = port;
    }
    Ok((ip, vec![udp, tcp]))
}

fn parse_url(scheme: &str, rest: &str) -> anyhow::Result<(IpAddr, Vec<ConnectionConfig>)> {
    let (rest, server_name) = match rest.split_once('#') {
        Some((r, name)) if !name.is_empty() => (r, Some(name)),
        _ => (rest, None),
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let (ip, port) = parse_ip_port(hostport)?;
    let scheme = scheme.to_ascii_lowercase();
    let connections = match scheme.as_str() {
        "udp" => vec![with_port(ConnectionConfig::udp(), port)],
        "tcp" => vec![with_port(ConnectionConfig::tcp(), port)],
        "udp+tcp" | "tcp+udp" => vec![
            with_port(ConnectionConfig::udp(), port),
            with_port(ConnectionConfig::tcp(), port),
        ],
        "tls" | "dot" => {
            let name = tls_name(ip, server_name)?;
            vec![with_port(ConnectionConfig::tls(name), port)]
        }
        "https" | "doh" => {
            let name = tls_name(ip, server_name)?;
            let path = path.map(Arc::from);
            vec![with_port(ConnectionConfig::https(name, path), port)]
        }
        "quic" | "doq" => {
            let name = tls_name(ip, server_name)?;
            vec![with_port(ConnectionConfig::quic(name), port)]
        }
        "h3" | "doh3" => {
            let name = tls_name(ip, server_name)?;
            let path = path.map(Arc::from);
            vec![with_port(ConnectionConfig::h3(name, path), port)]
        }
        other => bail!("unsupported DNS protocol '{other}'"),
    };
    Ok((ip, connections))
}

fn tls_name(ip: IpAddr, server_name: Option<&str>) -> anyhow::Result<Arc<str>> {
    match server_name {
        Some(n) => Ok(Arc::from(n)),
        None => bail!(
            "encrypted DNS for {ip} needs a TLS server name (e.g. tls://{ip}:853#dns.example)"
        ),
    }
}

fn with_port(mut conn: ConnectionConfig, port: Option<u16>) -> ConnectionConfig {
    if let Some(port) = port {
        conn.port = port;
    }
    conn
}

fn parse_ip_port(s: &str) -> anyhow::Result<(IpAddr, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_s, after) = rest
            .split_once(']')
            .context("invalid IPv6 address in brackets")?;
        let ip: IpAddr = ip_s.parse().context("invalid IPv6 address")?;
        let port = if after.is_empty() {
            None
        } else {
            let p = after
                .strip_prefix(':')
                .context("expected :port after IPv6]")?;
            Some(p.parse().context("invalid port")?)
        };
        return Ok((ip, port));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, None));
    }
    if let Some((host, port)) = s.rsplit_once(':')
        && let Ok(ip) = host.parse::<IpAddr>()
        && ip.is_ipv4()
    {
        return Ok((ip, Some(port.parse().context("invalid port")?)));
    }
    bail!("nameserver host must be an IP address (got {s})")
}

#[cfg(test)]
pub fn connection_summary(ns: &NameServerConfig) -> Vec<(ProtocolKind, u16)> {
    ns.connections
        .iter()
        .map(|c| (ProtocolKind::from(&c.protocol), c.port))
        .collect()
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
}

#[cfg(test)]
impl From<&hickory_resolver::config::ProtocolConfig> for ProtocolKind {
    fn from(p: &hickory_resolver::config::ProtocolConfig) -> Self {
        match p {
            ProtocolConfig::Udp => Self::Udp,
            ProtocolConfig::Tcp => Self::Tcp,
            ProtocolConfig::Tls { .. } => Self::Tls,
            ProtocolConfig::Https { .. } => Self::Https,
            ProtocolConfig::Quic { .. } => Self::Quic,
            ProtocolConfig::H3 { .. } => Self::H3,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn ns(spec: &str) -> NameServerConfig {
        match parse_upstream(&[spec.into()]).unwrap() {
            UpstreamSource::Config(c) => c.name_servers.into_iter().next().unwrap(),
            UpstreamSource::System => panic!("system"),
        }
    }

    #[rstest]
    #[case::custom_udp_port("udp://10.0.0.9:5353", vec![(ProtocolKind::Udp, 5353)])]
    #[case::plain_ip_is_udp_and_tcp("1.1.1.1", vec![(ProtocolKind::Udp, 53), (ProtocolKind::Tcp, 53)])]
    #[case::ip_with_port_applies_to_both("8.8.8.8:5353", vec![(ProtocolKind::Udp, 5353), (ProtocolKind::Tcp, 5353)])]
    #[case::tls("tls://1.1.1.1:853#cloudflare-dns.com", vec![(ProtocolKind::Tls, 853)])]
    #[case::https("https://1.1.1.1/dns-query#cloudflare-dns.com", vec![(ProtocolKind::Https, 443)])]
    #[case::quic("quic://1.1.1.1:853#cloudflare-dns.com", vec![(ProtocolKind::Quic, 853)])]
    #[case::h3("h3://1.1.1.1:443/dns-query#cloudflare-dns.com", vec![(ProtocolKind::H3, 443)])]
    #[case::ipv6_bracket("udp://[2001:db8::1]:5353", vec![(ProtocolKind::Udp, 5353)])]
    fn single_upstream_maps_to_expected_connections(
        #[case] spec: &str,
        #[case] expected: Vec<(ProtocolKind, u16)>,
    ) {
        assert_eq!(connection_summary(&ns(spec)), expected, "{spec}");
    }

    #[test]
    fn tls_requires_server_name_and_keeps_port() {
        let n = ns("tls://1.1.1.1:853#cloudflare-dns.com");
        assert_eq!(connection_summary(&n), vec![(ProtocolKind::Tls, 853)]);
        match &n.connections[0].protocol {
            ProtocolConfig::Tls { server_name } => {
                assert_eq!(server_name.as_ref(), "cloudflare-dns.com")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn system_mode() {
        match parse_upstream(&["system".into()]).unwrap() {
            UpstreamSource::System => {}
            UpstreamSource::Config(_) => panic!("expected system"),
        }
    }

    #[test]
    fn system_mixed_is_error() {
        assert!(parse_upstream(&["system".into(), "1.1.1.1".into()]).is_err());
    }

    #[test]
    fn merges_connections_for_same_ip() {
        match parse_upstream(&[
            "udp://1.1.1.1:53".into(),
            "tls://1.1.1.1:853#cloudflare-dns.com".into(),
        ])
        .unwrap()
        {
            UpstreamSource::Config(c) => {
                assert_eq!(c.name_servers.len(), 1);
                assert_eq!(
                    connection_summary(&c.name_servers[0]),
                    vec![(ProtocolKind::Udp, 53), (ProtocolKind::Tls, 853)]
                );
            }
            UpstreamSource::System => panic!("config"),
        }
    }

    #[test]
    fn multiple_ips_keep_order() {
        match parse_upstream(&["10.0.0.1:53".into(), "10.0.0.2:54".into()]).unwrap() {
            UpstreamSource::Config(c) => {
                assert_eq!(c.name_servers[0].ip.to_string(), "10.0.0.1");
                assert_eq!(c.name_servers[1].ip.to_string(), "10.0.0.2");
                assert_eq!(c.name_servers[1].connections[0].port, 54);
            }
            UpstreamSource::System => panic!("config"),
        }
    }
}
