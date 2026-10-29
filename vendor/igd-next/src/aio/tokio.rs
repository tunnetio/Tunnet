//! Tokio abstraction for the aio [`Gateway`].

use bytes::Bytes;
use futures::prelude::*;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Body;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::{net::UdpSocket, time::timeout};

use super::{Provider, HEADER_NAME, MAX_RESPONSE_SIZE};
#[cfg(feature = "ipv6")]
use crate::aio::Ipv6FirewallGateway;
use crate::common::messages::search_requests;
use crate::common::options::{DEFAULT_REQUEST_TIMEOUT, DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES, RESPONSE_TIMEOUT};
use crate::common::{endpoint, parsing, SearchOptions};
use crate::errors::SearchError;
use crate::{aio::Gateway, RequestError};
use log::debug;

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

/// Tokio provider for the [`Gateway`].
#[derive(Debug, Clone, Default)]
pub struct Tokio {
    /// Native authority applied before each HTTP connection.
    pub tcp: Option<netwatch::TcpSocketConfig>,
}

impl Provider for Tokio {
    async fn send_async(&self, url: &str, action: &str, body: &str) -> Result<String, RequestError> {
        // A link-local gateway can only be reached on a specific interface (the address's zone id),
        // which the hyper client cannot carry through a URL, so connect to the scoped address
        // directly via hyper's low-level connection API.
        if let Some((addr, path)) = scoped_link_local_target(url) {
            let headers = [(HEADER_NAME, action), ("Content-Type", "text/xml")];
            let send = raw_http_request(addr, "POST", &path, &headers, Some(body.to_string()), self.tcp);
            let bytes = timeout(DEFAULT_REQUEST_TIMEOUT, send).await??;
            return Ok(String::from_utf8(bytes)?);
        }

        let client = http_client(self.tcp);

        let body = body.to_string();

        let req = Request::builder()
            .uri(url)
            .method("POST")
            .header(HEADER_NAME, action)
            .header(CONTENT_TYPE, "text/xml")
            .header(CONTENT_LENGTH, body.len() as u64)
            .body(body)?;

        let send = async {
            let resp = client.request(req).await?;
            let body = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|e| RequestError::InvalidResponse(format!("could not read response body: {e}")))?
                .to_bytes();
            let string = String::from_utf8(body.to_vec())?;
            Ok::<_, RequestError>(string)
        };

        timeout(DEFAULT_REQUEST_TIMEOUT, send).await?
    }
}

/// Search for a gateway with the provided options.
pub async fn search_gateway(options: SearchOptions) -> Result<Gateway<Tokio>, SearchError> {
    let tcp = options.tcp;
    let discovered = search_device(options, SearchTarget::Wan).await?;
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
        provider: Tokio { tcp },
    })
}

/// Search for a gateway that exposes an IPv6 firewall service.
///
/// Use `SearchOptions::ipv6(scope_id)` to search over an IPv6 link.
#[cfg(feature = "ipv6")]
pub async fn search_ipv6_firewall_gateway(options: SearchOptions) -> Result<Ipv6FirewallGateway<Tokio>, SearchError> {
    let tcp = options.tcp;
    let discovered = search_device(options, SearchTarget::Firewall).await?;
    let control_url = discovered
        .urls
        .ipv6_firewall_control_url
        .ok_or(SearchError::InvalidResponse)?;
    Ok(Ipv6FirewallGateway::new(
        discovered.addr,
        discovered.root_url,
        control_url,
        Tokio { tcp },
    ))
}

async fn search_device(options: SearchOptions, target: SearchTarget) -> Result<DiscoveredDevice, SearchError> {
    let search_timeout = options.timeout.unwrap_or(DEFAULT_TIMEOUT);
    match timeout(search_timeout, discover(options, target)).await {
        Ok(Ok(discovered)) => Ok(discovered),
        Ok(Err(err)) => Err(err),
        Err(_err) => {
            // Timeout
            Err(SearchError::NoResponseWithinTimeout)
        }
    }
}

async fn discover(options: SearchOptions, target: SearchTarget) -> Result<DiscoveredDevice, SearchError> {
    // Create socket for future calls
    let tcp = options.tcp;
    let mut socket = ssdp_socket(&options).await?;

    send_search_request(&mut socket, options.broadcast_address).await?;
    let response_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);

    loop {
        let search_response = receive_search_response(&mut socket);

        // Receive search response
        let (response_body, from) = match timeout(response_timeout, search_response).await {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                debug!("error while receiving broadcast response: {err}");
                continue;
            }
            Err(_) => {
                debug!("timeout while receiving broadcast response");
                continue;
            }
        };

        let (addr, root_url) = match handle_broadcast_resp(&from, &response_body) {
            Ok(v) => v,
            Err(e) => {
                debug!("error handling broadcast response: {}", e);
                continue;
            }
        };

        if endpoint::validate_location(addr, from, &options.allowed_gateway_ips).is_err() {
            debug!("skipping gateway {addr} with an untrusted location");
            continue;
        }

        if !options.gateway_ip_version.accepts(addr.ip()) {
            debug!("skipping gateway {}: not the requested IP version", addr);
            continue;
        }

        let urls = match get_control_urls(&addr, &root_url, &options.allowed_gateway_ips, tcp).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control URLs: {}", e);
                continue;
            }
        };

        let control_schema = match target {
            SearchTarget::Wan => {
                let Some(wan) = urls.wan.as_ref() else {
                    continue;
                };
                match get_control_schemas(&addr, &wan.control_schema_url, tcp).await {
                    Ok(schema) => Some(schema),
                    Err(e) => {
                        debug!("error getting control schemas: {}", e);
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
}

async fn send_search_request(socket: &mut UdpSocket, addr: SocketAddr) -> Result<(), SearchError> {
    debug!(
        "sending broadcast request to: {} on interface: {:?}",
        addr,
        socket.local_addr()
    );
    let mut sent_any = false;
    let mut last_send_error: Option<std::io::Error> = None;
    for request in search_requests(&addr) {
        match socket.send_to(request.as_bytes(), &addr).await {
            Ok(_) => sent_any = true,
            Err(e) => {
                debug!("failed to send search request: {e}");
                last_send_error = Some(e);
            }
        }
    }
    if sent_any {
        Ok(())
    } else {
        Err(last_send_error.expect("at least one send attempt failed").into())
    }
}

async fn receive_search_response(socket: &mut UdpSocket) -> Result<(Vec<u8>, SocketAddr), SearchError> {
    let mut buff = [0u8; MAX_RESPONSE_SIZE];
    let (n, from) = socket.recv_from(&mut buff).map_err(SearchError::from).await?;
    debug!("received broadcast response from: {}", from);
    Ok((buff[..n].to_vec(), from))
}

// Handle a UDP response message.
fn handle_broadcast_resp(from: &SocketAddr, data: &[u8]) -> Result<(SocketAddr, String), SearchError> {
    debug!("handling broadcast response from: {}", from);

    // Convert response to text.
    let text = std::str::from_utf8(data).map_err(SearchError::from)?;

    // Parse socket address and path.
    let (addr, root_url) = parsing::parse_search_result(text)?;

    let addr = crate::common::linklocal::apply_response_scope(addr, *from);

    Ok((addr, root_url))
}

async fn get_control_urls(
    addr: &SocketAddr,
    path: &str,
    allowed: &[std::net::IpAddr],
    tcp: Option<netwatch::TcpSocketConfig>,
) -> Result<parsing::DeviceUrls, SearchError> {
    let target = endpoint::target(*addr, path)?;
    let resp = if crate::common::linklocal::is_scoped_link_local(&target.addr) {
        raw_http_request(target.addr, "GET", &target.path_and_query, &[], None, tcp)
            .await
            .map_err(|_| SearchError::InvalidResponse)?
    } else {
        let uri = match target.transport_url().parse() {
            Ok(uri) => uri,
            Err(err) => return Err(SearchError::from(err)),
        };

        debug!("requesting control url from: {uri}");
        let client: Client<_, Empty<Bytes>> = http_client(tcp);

        Limited::new(client.get(uri).await?.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| SearchError::InvalidResponse)?
            .to_bytes()
            .to_vec()
    };

    debug!("handling control response from: {addr}");
    let mut urls = parsing::parse_device_urls(std::io::Cursor::new(&resp))?;
    endpoint::resolve_device_urls(&mut urls, *addr, path, allowed)?;
    Ok(urls)
}

async fn get_control_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
    tcp: Option<netwatch::TcpSocketConfig>,
) -> Result<HashMap<String, Vec<String>>, SearchError> {
    let target = endpoint::target(*addr, control_schema_url)?;
    let resp = if crate::common::linklocal::is_scoped_link_local(&target.addr) {
        raw_http_request(target.addr, "GET", &target.path_and_query, &[], None, tcp)
            .await
            .map_err(|_| SearchError::InvalidResponse)?
    } else {
        let uri = match target.transport_url().parse() {
            Ok(uri) => uri,
            Err(err) => return Err(SearchError::from(err)),
        };

        debug!("requesting control schema from: {uri}");
        let client: Client<_, Empty<Bytes>> = http_client(tcp);

        Limited::new(client.get(uri).await?.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| SearchError::InvalidResponse)?
            .to_bytes()
            .to_vec()
    };

    debug!("handling schema response from: {addr}");
    let c = std::io::Cursor::new(&resp);
    parsing::parse_schemas(c)
}

/// Reach a link-local gateway by connecting directly to its scoped socket address (which a URL
/// cannot carry) and speaking HTTP/1.1 over hyper's low-level connection API.
async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<String>,
    tcp: Option<netwatch::TcpSocketConfig>,
) -> Result<Vec<u8>, RequestError> {
    use hyper::header::{CONNECTION, HOST};

    use std::task::Poll;

    let host = crate::common::linklocal::host_without_zone(&addr);
    let stream = match tcp {
        Some(config) => netwatch::connect_tcp(addr, config).await?,
        None => tokio::net::TcpStream::connect(addr).await?,
    };
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    let body = body.unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, body.len() as u64);
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;

    let request = async move {
        let resp = sender.send_request(req).await?;
        let bytes = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| RequestError::InvalidResponse(format!("could not read response body: {e}")))?
            .to_bytes();
        Ok::<Vec<u8>, RequestError>(bytes.to_vec())
    };

    let mut request = std::pin::pin!(request);
    let mut conn = std::pin::pin!(conn);
    let mut conn_done = false;

    futures::future::poll_fn(move |cx| {
        if !conn_done {
            match conn.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RequestError::HyperError(e))),
                Poll::Ready(Ok(())) => conn_done = true,
                Poll::Pending => {}
            }
        }
        request.as_mut().poll(cx)
    })
    .await
}

/// If `url` targets a scoped IPv6 link-local address, return that address (with its zone id) and the
/// request path. A normal URL is served by the regular hyper client, so this returns `None`.
fn scoped_link_local_target(url: &str) -> Option<(SocketAddr, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let addr: SocketAddr = authority.parse().ok()?;
    crate::common::linklocal::is_scoped_link_local(&addr).then_some((addr, path))
}

async fn ssdp_socket(options: &SearchOptions) -> Result<UdpSocket, SearchError> {
    let socket = match options.udp {
        Some(config) => {
            let socket = netwatch::bind_udp(options.bind_addr, options.broadcast_address, config)?;
            if let Some(interface) = config.interface {
                let address = interface.ipv4_address()?;
                socket2::SockRef::from(&socket).set_multicast_if_v4(&address)?;
            }
            tokio::net::UdpSocket::from_std(socket)?
        }
        None => UdpSocket::bind(options.bind_addr).await?,
    };
    Ok(socket)
}

fn http_client<B>(tcp: Option<netwatch::TcpSocketConfig>) -> Client<HttpConnector, B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut connector = HttpConnector::new();
    if let Some(config) = tcp {
        connector.set_socket_initializer(std::sync::Arc::new(move |socket, destination| {
            netwatch::configure_tcp_socket(socket, destination, config)
        }));
    }
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn refuse_udp(_: &std::net::UdpSocket) -> std::io::Result<()> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
    }

    fn refuse_tcp(_: &std::net::TcpStream) -> std::io::Result<()> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
    }

    fn allow_tcp(_: &std::net::TcpStream) -> std::io::Result<()> {
        Ok(())
    }

    fn gateway_for(addr: SocketAddr, tcp: Option<netwatch::TcpSocketConfig>) -> Gateway<Tokio> {
        Gateway {
            addr,
            root_url: "/".into(),
            control_url: "/".into(),
            control_schema_url: "/".into(),
            control_schema: HashMap::new(),
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
            #[cfg(feature = "ipv6")]
            ipv6_firewall_control_url: None,
            provider: Tokio { tcp },
        }
    }

    #[tokio::test]
    async fn native_authority_fails_closed_and_allows_scoped_http() {
        let refused_tcp = Some(netwatch::TcpSocketConfig {
            interface: None,
            initialize: Some(refuse_tcp),
        });
        let denied = Tokio { tcp: refused_tcp }
            .send_async("http://[fe80::1%1]:80/", "test", "test")
            .await;
        assert!(matches!(denied, Err(RequestError::IoError(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gateway = gateway_for(listener.local_addr().unwrap(), refused_tcp);
        let denied = tokio::time::timeout(Duration::from_secs(1), gateway.get_external_ip())
            .await
            .expect("refused http connect hung");
        assert!(denied.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let gateway = gateway_for(
            listener.local_addr().unwrap(),
            Some(netwatch::TcpSocketConfig {
                interface: None,
                initialize: Some(allow_tcp),
            }),
        );
        let request = tokio::spawn(async move { gateway.get_external_ip().await });
        let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("scoped http connect did not reach the listener")
            .unwrap();
        drop(accepted);
        drop(listener);
        let requested = tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .expect("allowed http connect hung")
            .unwrap();
        assert!(requested.is_err());

        let refused = SearchOptions {
            timeout: Some(Duration::from_millis(20)),
            udp: Some(netwatch::SocketConfig {
                interface: None,
                initialize: Some(refuse_udp),
            }),
            tcp: refused_tcp,
            ..SearchOptions::default()
        };
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(1), search_gateway(refused.clone())).await {
                Ok(Err(SearchError::IoError(err))) => {
                    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                }
                other => panic!("unprotected or unexpected search result: {other:?}"),
            }
        }
    }
    #[tokio::test]
    async fn http_response_is_bounded_before_end_of_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            socket.read(&mut request).await.unwrap();
            socket
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_RESPONSE_BYTES * 2).as_bytes())
                .await
                .unwrap();
            socket.write_all(&vec![b'x'; MAX_RESPONSE_BYTES + 1]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            Tokio::default().send_async(&format!("http://{address}/"), "test", "test"),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(RequestError::InvalidResponse(error)) if error.contains("length limit exceeded")));
        server.abort();
        let _ = server.await;
    }
}
