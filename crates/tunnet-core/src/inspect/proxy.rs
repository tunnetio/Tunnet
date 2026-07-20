//! Local HTTP reverse-proxy with inspection (Direct mode / local-only).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::InspectorHub;
use super::http_tee::inspect_bidirectional;
use super::store::ExchangeStore;

/// Accept connections on `listen`, tee HTTP through the inspector, forward to `upstream`.
pub async fn run_local_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    store: ExchangeStore,
    tunnel_id: String,
    mut stop: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = &mut stop => {
                tracing::info!(%upstream, "local inspect proxy stopped");
                break;
            }
            accepted = listener.accept() => {
                let (client, peer) = accepted.context("accept")?;
                let _ = client.set_nodelay(true);
                let store = store.clone();
                let tid = tunnel_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy_one(client, upstream, store, tid).await {
                        tracing::debug!(?e, %peer, "local inspect connection ended");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn proxy_one(
    client: tokio::net::TcpStream,
    upstream: SocketAddr,
    store: ExchangeStore,
    tunnel_id: String,
) -> anyhow::Result<()> {
    let upstream_tcp = tokio::net::TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connect upstream {upstream}"))?;
    let _ = upstream_tcp.set_nodelay(true);

    let (client_read, client_write) = client.into_split();
    let (up_read, up_write) = upstream_tcp.into_split();

    // Client → upstream is the "request" direction (like relay_recv).
    inspect_bidirectional(
        client_read,
        client_write,
        up_read,
        up_write,
        None,
        store,
        tunnel_id,
    )
    .await
}

/// Bind a listener for the local inspect forward URL.
pub async fn bind_forward_listener(
    listen: Option<&str>,
) -> anyhow::Result<(TcpListener, SocketAddr)> {
    let addr: SocketAddr = match listen {
        Some(s) => s.parse().context("invalid local listen address")?,
        None => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    };
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind local inspect forward on {addr}"))?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

/// Start inspector UI + local forward proxy; returns (forward_url, inspector_url, stop_tx).
pub async fn start_local_inspect_session(
    hub: &InspectorHub,
    tunnel_id: &str,
    upstream: SocketAddr,
    inspect_addr: Option<&str>,
    listen: Option<&str>,
) -> anyhow::Result<(String, String, oneshot::Sender<()>)> {
    let inspector_url = hub
        .register_tunnel(tunnel_id, upstream, inspect_addr)
        .await?;
    let (listener, bound) = bind_forward_listener(listen).await?;
    let forward_url = format!("http://{bound}");

    let (stop_tx, stop_rx) = oneshot::channel();
    let store = hub.store();
    let tid = tunnel_id.to_string();
    let hub = Arc::new(hub.clone());
    let tid_cleanup = tid.clone();

    tokio::spawn(async move {
        let _ = run_local_proxy(listener, upstream, store, tid, stop_rx).await;
        hub.unregister_tunnel(&tid_cleanup);
    });

    Ok((forward_url, inspector_url, stop_tx))
}
