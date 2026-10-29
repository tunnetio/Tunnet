use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::time::{Duration, Instant};

use attohttpc::{Method, RequestBuilder};
use log::debug;

use crate::common::messages::search_requests;
use crate::common::options::{DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES, RESPONSE_TIMEOUT};
use crate::common::{self, endpoint, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::gateway::Gateway;
#[cfg(feature = "ipv6")]
use crate::gateway::Ipv6FirewallGateway;

enum SearchTarget {
    Wan,
    #[cfg(feature = "ipv6")]
    Firewall,
}

struct DiscoveredDevice {
    addr: SocketAddr,
    root_url: String,
    urls: parsing::DeviceUrls,
    control_schema: Option<HashMap<String, Vec<String>>>,
}

/// Search gateway, using the given `SearchOptions`.
///
/// The default `SearchOptions` should suffice in most cases.
/// It can be created with `Default::default()` or `SearchOptions::default()`.
///
/// # Example
/// ```no_run
/// use igd_next::{search_gateway, SearchOptions, Result};
///
/// fn main() -> Result {
///     let gateway = search_gateway(Default::default())?;
///     let ip = gateway.get_external_ip()?;
///     println!("External IP address: {}", ip);
///     Ok(())
/// }
/// ```
pub fn search_gateway(options: SearchOptions) -> Result<Gateway, SearchError> {
    let discovered = discover(options, SearchTarget::Wan)?;
    let wan = discovered.urls.wan.ok_or(SearchError::InvalidResponse)?;
    let control_schema = discovered.control_schema.ok_or(SearchError::InvalidResponse)?;
    Ok(Gateway {
        addr: discovered.addr,
        root_url: discovered.root_url,
        control_url: wan.control_url,
        control_schema_url: wan.control_schema_url,
        control_schema,
        service_type: wan.service_type,
        #[cfg(feature = "ipv6")]
        ipv6_firewall_control_url: discovered.urls.ipv6_firewall_control_url,
    })
}

/// Search for a gateway that exposes an IPv6 firewall service.
///
/// Use `SearchOptions::ipv6(scope_id)` to search over an IPv6 link.
#[cfg(feature = "ipv6")]
pub fn search_ipv6_firewall_gateway(options: SearchOptions) -> Result<Ipv6FirewallGateway, SearchError> {
    let discovered = discover(options, SearchTarget::Firewall)?;
    let control_url = discovered
        .urls
        .ipv6_firewall_control_url
        .ok_or(SearchError::InvalidResponse)?;
    Ok(Ipv6FirewallGateway {
        addr: discovered.addr,
        root_url: discovered.root_url,
        control_url,
    })
}

fn discover(options: SearchOptions, target: SearchTarget) -> Result<DiscoveredDevice, SearchError> {
    if options.udp.is_some() || options.tcp.is_some() {
        return Err(SearchError::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "native underlay search requires the tokio gateway",
        )));
    }
    let start = Instant::now();
    let max_time = options.timeout.unwrap_or(DEFAULT_TIMEOUT);

    let socket = UdpSocket::bind(options.bind_addr)?;

    let response_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);

    let mut sent_any = false;
    let mut last_send_error: Option<std::io::Error> = None;
    for request in search_requests(&options.broadcast_address) {
        match socket.send_to(request.as_bytes(), options.broadcast_address) {
            Ok(_) => sent_any = true,
            Err(e) => {
                debug!("failed to send search request: {e}");
                last_send_error = Some(e);
            }
        }
    }
    if !sent_any {
        return Err(last_send_error.expect("at least one send attempt failed").into());
    }

    while start.elapsed() < max_time {
        let remaining = max_time.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        // limit read, to the remaining time available
        socket.set_read_timeout(Some(response_timeout.min(remaining)))?;

        let mut buf = [0u8; 1500];
        let (read, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                debug!("error while receiving broadcast response: {e}");
                continue;
            }
        };

        let text = match str::from_utf8(&buf[..read]) {
            Ok(text) => text,
            Err(e) => {
                debug!("received a non-utf8 broadcast response: {e}");
                continue;
            }
        };

        let (addr, root_url) = match parsing::parse_search_result(text) {
            Ok(v) => v,
            Err(e) => {
                debug!("could not parse broadcast response: {e}");
                continue;
            }
        };

        // A link-local LOCATION carries no zone id; inherit it from the response source so the
        // gateway can be reached on the interface it answered on.
        let addr = common::linklocal::apply_response_scope(addr, from);

        if endpoint::validate_location(addr, from, &options.allowed_gateway_ips).is_err() {
            debug!("skipping gateway {addr} with an untrusted location");
            continue;
        }

        if !options.gateway_ip_version.accepts(addr.ip()) {
            debug!("skipping gateway {addr}. Not the requested IP version");
            continue;
        }

        let urls = match get_control_urls(
            &addr,
            &root_url,
            &options.allowed_gateway_ips,
            max_time.saturating_sub(start.elapsed()),
        ) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "Error has occurred while getting control urls. error: {}, addr: {}, root_url: {}",
                    e, addr, root_url
                );
                continue;
            }
        };

        let control_schema = match target {
            SearchTarget::Wan => {
                let Some(wan) = urls.wan.as_ref() else {
                    continue;
                };
                match get_schemas(&addr, &wan.control_schema_url, max_time.saturating_sub(start.elapsed())) {
                    Ok(schema) => Some(schema),
                    Err(e) => {
                        debug!(
                            "Error has occurred while getting schemas. error: {}, addr: {}, control_schema_url: {}",
                            e, addr, wan.control_schema_url
                        );
                        continue;
                    }
                }
            }
            #[cfg(feature = "ipv6")]
            SearchTarget::Firewall => {
                if urls.ipv6_firewall_control_url.is_none() {
                    continue;
                }
                None
            }
        };

        return Ok(DiscoveredDevice {
            addr,
            root_url,
            urls,
            control_schema,
        });
    }

    Err(SearchError::NoResponseWithinTimeout)
}

fn get_control_urls(
    addr: &SocketAddr,
    root_url: &str,
    allowed: &[std::net::IpAddr],
    timeout: Duration,
) -> Result<parsing::DeviceUrls, SearchError> {
    let target = endpoint::target(*addr, root_url)?;
    let body = if common::linklocal::is_scoped_link_local(&target.addr) {
        common::linklocal::raw_http_request(
            target.addr,
            "GET",
            &target.path_and_query,
            &[],
            None,
            timeout,
            MAX_RESPONSE_BYTES,
        )?
    } else {
        let response = match RequestBuilder::try_new(Method::GET, target.transport_url()) {
            Ok(request_builder) => request_builder
                .follow_redirects(false)
                .connect_timeout(timeout)
                .timeout(timeout)
                .send()?,
            Err(error) => return Err(SearchError::HttpError(error)),
        };
        common::read_response_body(response, MAX_RESPONSE_BYTES)?
    };
    let mut urls = parsing::parse_device_urls(&body[..])?;
    endpoint::resolve_device_urls(&mut urls, *addr, root_url, allowed)?;
    Ok(urls)
}

fn get_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
    timeout: Duration,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let target = endpoint::target(*addr, control_schema_url)?;
    let body = if common::linklocal::is_scoped_link_local(&target.addr) {
        common::linklocal::raw_http_request(
            target.addr,
            "GET",
            &target.path_and_query,
            &[],
            None,
            timeout,
            MAX_RESPONSE_BYTES,
        )?
    } else {
        let response = match RequestBuilder::try_new(Method::GET, target.transport_url()) {
            Ok(request_builder) => request_builder
                .follow_redirects(false)
                .connect_timeout(timeout)
                .timeout(timeout)
                .send()?,
            Err(error) => return Err(SearchError::HttpError(error)),
        };
        common::read_response_body(response, MAX_RESPONSE_BYTES)?
    };
    parsing::parse_schemas(&body[..])
}

#[cfg(test)]
mod native_tests {
    use super::*;

    #[test]
    fn protected_sync_search_refuses_before_discovery() {
        fn refused(result: Result<(), SearchError>) {
            assert!(matches!(result, Err(SearchError::IoError(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && error.to_string() == "native underlay search requires the tokio gateway"));
        }
        for udp in [true, false] {
            let mut options = SearchOptions::default();
            if udp {
                options.udp = Some(netwatch::SocketConfig::default());
            } else {
                options.tcp = Some(netwatch::TcpSocketConfig::default());
            }
            refused(search_gateway(options.clone()).map(|_| ()));
            #[cfg(feature = "ipv6")]
            refused(search_ipv6_firewall_gateway(options).map(|_| ()));
        }
    }
}
