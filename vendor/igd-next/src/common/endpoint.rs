use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use url::{Host, Url};

use crate::common::{linklocal, parsing::DeviceUrls};
use crate::errors::SearchError;

pub struct Endpoint {
    pub addr: SocketAddr,
    pub path_and_query: String,
}

impl Endpoint {
    pub fn transport_url(&self) -> String {
        format!("http://{}{path}", self.addr, path = self.path_and_query)
    }
}

pub fn path_and_query(url: &Url) -> String {
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

pub fn validate_location(addr: SocketAddr, from: SocketAddr, allowed: &[IpAddr]) -> Result<(), SearchError> {
    let ip = addr.ip();
    if addr.port() == 0 || !trusted_ip(ip, from.ip(), allowed) {
        return Err(SearchError::InvalidResponse);
    }
    Ok(())
}

pub fn resolve_device_urls(
    urls: &mut DeviceUrls,
    descriptor_addr: SocketAddr,
    descriptor_path: &str,
    allowed: &[IpAddr],
) -> Result<(), SearchError> {
    let descriptor = descriptor_url(descriptor_addr, descriptor_path)?;
    let base = match urls.url_base.as_deref() {
        Some(value) => descriptor.join(value).map_err(|_| SearchError::InvalidResponse)?,
        None => descriptor,
    };

    urls.wan = urls.wan.take().and_then(|mut wan| {
        wan.control_schema_url = resolve_reference(&base, &wan.control_schema_url, descriptor_addr, allowed).ok()?;
        wan.control_url = resolve_reference(&base, &wan.control_url, descriptor_addr, allowed).ok()?;
        Some(wan)
    });
    #[cfg(feature = "ipv6")]
    {
        urls.ipv6_firewall_control_url = urls
            .ipv6_firewall_control_url
            .take()
            .and_then(|firewall| resolve_reference(&base, &firewall, descriptor_addr, allowed).ok());
    }
    Ok(())
}

pub fn target(addr: SocketAddr, reference: &str) -> Result<Endpoint, SearchError> {
    let base = descriptor_url(addr, "/")?;
    let url = base.join(reference).map_err(|_| SearchError::InvalidResponse)?;
    endpoint_from_url(&url, addr)
}

fn resolve_reference(base: &Url, reference: &str, addr: SocketAddr, allowed: &[IpAddr]) -> Result<String, SearchError> {
    if reference.is_empty() {
        return Err(SearchError::InvalidResponse);
    }
    let url = base.join(reference).map_err(|_| SearchError::InvalidResponse)?;
    let endpoint = endpoint_from_url(&url, addr)?;
    if !trusted_ip(endpoint.addr.ip(), addr.ip(), allowed) {
        return Err(SearchError::InvalidResponse);
    }
    if endpoint.addr == addr {
        Ok(endpoint.path_and_query)
    } else {
        Ok(url.into())
    }
}

fn descriptor_url(addr: SocketAddr, path: &str) -> Result<Url, SearchError> {
    Url::parse(&format!("http://{}{path}", linklocal::host_without_zone(&addr)))
        .map_err(|_| SearchError::InvalidResponse)
}

fn endpoint_from_url(url: &Url, addr: SocketAddr) -> Result<Endpoint, SearchError> {
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(SearchError::InvalidResponse);
    }
    let ip = match url.host() {
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => return Err(SearchError::InvalidResponse),
    };
    let port = url.port_or_known_default().ok_or(SearchError::InvalidResponse)?;
    if port == 0 {
        return Err(SearchError::InvalidResponse);
    }
    let target_addr = match (ip, addr) {
        (IpAddr::V6(ip), SocketAddr::V6(hint))
            if ip == *hint.ip() || (linklocal::is_link_local(&ip) && hint.scope_id() != 0) =>
        {
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, hint.scope_id()))
        }
        _ => SocketAddr::new(ip, port),
    };
    Ok(Endpoint {
        addr: target_addr,
        path_and_query: path_and_query(url),
    })
}

fn trusted_ip(ip: IpAddr, expected: IpAddr, allowed: &[IpAddr]) -> bool {
    if allowed.contains(&ip) {
        return true;
    }
    ip == expected && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
}
