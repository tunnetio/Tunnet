//! Utilities used in [`iroh`](crate).

/// Creates a [`reqwest::ClientBuilder`] from a [`rustls::ClientConfig`] and our [`DnsResolver`].
///
/// In a browser context these options are not supported, so this function takes no arguments
/// if `wasm_browser` is enabled.
///
/// [`DnsResolver`]: crate::dns::DnsResolver
#[cfg(not(wasm_browser))]
pub(crate) fn reqwest_client_builder(
    tls_client_config: rustls::ClientConfig,
    dns_resolver: crate::dns::DnsResolver,
    config: Option<[Option<netwatch::TcpSocketConfig>; 2]>,
) -> reqwest::ClientBuilder {
    use self::reqwest_dns_resolver::ReqwestDnsResolver;

    let mut builder = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_client_config)
        .dns_resolver(ReqwestDnsResolver(dns_resolver));
    if let Some(config) = config {
        builder = builder
            .no_proxy()
            .tcp_socket_initializer(std::sync::Arc::new(move |socket, destination| {
                let config = config[usize::from(destination.is_ipv6())].ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "no authorized HTTP underlay for address family",
                    )
                })?;
                netwatch::configure_tcp_socket(socket, destination, config)
            }));
    }
    builder
}

#[cfg(wasm_browser)]
pub(crate) fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

#[cfg(not(wasm_browser))]
mod reqwest_dns_resolver {
    use std::net::SocketAddr;

    use iroh_dns::dns::{DNS_TIMEOUT, DnsResolver};

    use crate::address_lookup::DNS_STAGGERING_MS;

    /// Implementation of [`reqwest::dns::Resolve`] for [`DnsResolver`].
    ///
    /// Wrapped in a newtype to not expose this in the public iroh API.
    pub(super) struct ReqwestDnsResolver(pub(super) DnsResolver);

    impl reqwest::dns::Resolve for ReqwestDnsResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let this = self.0.clone();
            let name = name.as_str().to_string();
            Box::pin(async move {
                // Staggered so that a single unresponsive DNS server does not stall the
                // request for the full timeout.  Ideally this resolves **both** IPv4 and
                // IPv6 rather than racing them, but our resolver has no function for that
                // yet.
                let res = this
                    .lookup_ipv4_ipv6_staggered(name, DNS_TIMEOUT, DNS_STAGGERING_MS)
                    .await
                    // Collected eagerly: the returned iterator borrows the resolver, which
                    // does not outlive this future.
                    .map(|addrs| {
                        addrs
                            .map(|addr| SocketAddr::new(addr, 0))
                            .collect::<Vec<_>>()
                    });
                match res {
                    Ok(addrs) => {
                        let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
                        Ok(addrs)
                    }
                    Err(err) => {
                        let err: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
                        Err(err)
                    }
                }
            })
        }
    }
}

#[cfg(all(test, not(wasm_browser), feature = "tls-ring"))]
mod tests {
    #[tokio::test]
    async fn dependent_http_preserves_dns_underlay_authorization_after_reset() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resolver = crate::dns::DnsResolver::new();
        resolver.reset();
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let client = super::reqwest_client_builder(tls, resolver, Some([None; 2]))
            .build()
            .unwrap();
        assert!(
            client
                .get(format!("http://{}", listener.local_addr().unwrap()))
                .send()
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
}
