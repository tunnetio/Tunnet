use std::sync::Arc;

use tun_rs::AsyncDevice;
use tunnet_core::{ForwardingStore, PeerManager, PolicyEngine};

use crate::metrics::AgentMetrics;
use crate::tun_io::{DnsPool, TunWriter};

pub(crate) struct TaskExit {
    pub cancel: tokio_util::sync::CancellationToken,
    pub notify: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for TaskExit {
    fn drop(&mut self) {
        if !self.cancel.is_cancelled()
            && let Some(notify) = self.notify.take()
        {
            notify();
        }
    }
}

pub struct OutboundSpawn {
    pub tun: Arc<AsyncDevice>,
    pub writer: TunWriter,
    pub cancel: tokio_util::sync::CancellationToken,
    pub peers: PeerManager,
    pub policy: PolicyEngine,
    pub forwarding: ForwardingStore,
    pub metrics: AgentMetrics,
    pub dns: DnsPool,
    pub on_unexpected_end: Box<dyn FnOnce() + Send + 'static>,
}

pub fn spawn_outbound(spawn: OutboundSpawn) -> tokio::task::JoinHandle<()> {
    let OutboundSpawn {
        tun,
        writer,
        cancel,
        peers,
        policy,
        forwarding,
        metrics,
        dns,
        on_unexpected_end,
    } = spawn;
    tokio::spawn(async move {
        let _exit = TaskExit {
            cancel: cancel.clone(),
            notify: Some(on_unexpected_end),
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = crate::tun_io::run_outbound(crate::tun_io::OutboundDeps {
            tun,
            writer,
            peers,
            policy,
            forwarding,
            metrics,
            dns,
            }) => result,
        };
        if let Err(e) = result {
            tracing::error!(?e, "outbound TUN loop exited");
        }
    })
}

/// Extract the host part of a URL for underlay-pin resolution.
#[cfg(not(target_os = "android"))]
fn url_host(url: &str) -> &str {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Resolve IPv4 underlay pins from service URLs. Literals resolve inline;
/// hostnames resolve via DNS with a bounded timeout. Best-effort: unresolvable
/// names contribute nothing rather than blocking startup.
#[cfg(not(target_os = "android"))]
pub async fn resolve_underlay_hosts(urls: &[String]) -> Vec<std::net::Ipv4Addr> {
    let mut out = Vec::new();
    for url in urls {
        let host = url_host(url);
        if host.is_empty() {
            continue;
        }
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if !ip.is_loopback() && !ip.is_unspecified() && !out.contains(&ip) {
                out.push(ip);
            }
            continue;
        }
        let query = format!("{host}:443");
        let Ok(resolved) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::lookup_host(query),
        )
        .await
        else {
            continue;
        };
        let Ok(addrs) = resolved else { continue };
        for addr in addrs {
            if let std::net::IpAddr::V4(ip) = addr.ip()
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !out.contains(&ip)
                && out.len() < 16
            {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(not(target_os = "android"))]
#[cfg(test)]
mod underlay_host_tests {
    use super::resolve_underlay_hosts;

    #[tokio::test]
    async fn literal_hosts_pin_without_dns() {
        let hosts = resolve_underlay_hosts(&[
            "https://192.0.2.10:8443/x".to_string(),
            "http://[::1]/".to_string(),
        ])
        .await;
        assert_eq!(
            hosts,
            vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn unresolvable_names_contribute_nothing() {
        let hosts = resolve_underlay_hosts(&["https://nonexistent.invalid./".to_string()]).await;
        assert!(hosts.is_empty());
    }
}
