//! Tunnet Serve - TLS (or TCP) reverse proxy on the mesh interface → upstream.
//!
//! `tunnet serve 3000` listens on the agent's mesh IP with an internal-CA cert
//! and forwards decrypted traffic to a configurable upstream (default `127.0.0.1:port`).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tunnet_common::ws::ClientMsg;

use crate::ipc::protocol::ServeInfo;
use crate::routing::RoutingTable;

#[derive(Debug, Clone)]
pub struct ServeAcl {
    pub access_mode: String,
    pub allowed_tags: Vec<String>,
    pub allowed_endpoint_ids: Vec<String>,
}

impl Default for ServeAcl {
    fn default() -> Self {
        Self {
            access_mode: "all_peers".into(),
            allowed_tags: Vec::new(),
            allowed_endpoint_ids: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ServeManager {
    inner: Arc<Mutex<Inner>>,
    mesh_ip: Ipv4Addr,
    routes: RoutingTable,
    /// Optional WS client channel for ServePeerJoined / ServePeerLeft.
    client_tx: Arc<Mutex<Option<mpsc::Sender<ClientMsg>>>>,
    next_generation: Arc<AtomicU64>,
}

struct Inner {
    serves: HashMap<u16, ActiveServe>,
}

struct ActiveServe {
    info: ServeInfo,
    protocol: String,
    target_addr: SocketAddr,
    internal_hostname: String,
    /// True when started via control-plane `StartServe` (dashboard-managed).
    managed: bool,
    /// Live ACL - updated in place on access-control changes (no rebind).
    acl: Arc<ArcSwap<ServeAcl>>,
    generation: u64,
    stop: Option<oneshot::Sender<()>>,
    /// Signaled after the proxy task has dropped the listener.
    finished: Option<oneshot::Receiver<()>>,
}

impl ServeManager {
    pub fn new(mesh_ip: Ipv4Addr, routes: RoutingTable) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                serves: HashMap::new(),
            })),
            mesh_ip,
            routes,
            client_tx: Arc::new(Mutex::new(None)),
            next_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Wire control-plane reporting (call once after WS channel is created).
    pub fn set_client_tx(&self, tx: mpsc::Sender<ClientMsg>) {
        *self.client_tx.lock() = Some(tx);
    }

    pub fn client_tx(&self) -> Option<mpsc::Sender<ClientMsg>> {
        self.client_tx.lock().clone()
    }

    pub fn list(&self) -> Vec<ServeInfo> {
        self.inner
            .lock()
            .serves
            .values()
            .map(|s| s.info.clone())
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        &self,
        id: String,
        port: u16,
        protocol: &str,
        internal_hostname: &str,
        certificate_pem: Option<&str>,
        private_key_pem: Option<&str>,
        acl: ServeAcl,
        // Upstream to proxy to (defaults to `127.0.0.1:port` when `None`).
        target_addr: Option<SocketAddr>,
        // When true, this serve is owned by the control plane and subject to reconcile.
        managed: bool,
    ) -> anyhow::Result<ServeInfo> {
        let local = target_addr.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, port)));

        // Access-control-only updates must not rebind: on Windows, stopping and
        // immediately rebinding the same mesh IP:port races (WSAEADDRINUSE / 10048)
        // and can leave the previous listener (old ACL) still accepting.
        {
            let mut guard = self.inner.lock();
            if let Some(existing) = guard.serves.values_mut().find(|s| s.info.id == id)
                && existing.info.port == port
                && existing.protocol == protocol
                && existing.target_addr == local
                && existing.internal_hostname == internal_hostname
            {
                existing.acl.store(Arc::new(acl));
                if managed {
                    existing.managed = true;
                }
                let access_mode = existing.acl.load().access_mode.clone();
                let info = existing.info.clone();
                tracing::info!(port, protocol, %access_mode, "serve ACL updated in place");
                return Ok(info);
            }
        }

        // Full replace: await old listener teardown before binding again.
        {
            let port_to_stop = {
                let guard = self.inner.lock();
                if let Some(existing) = guard.serves.values().find(|s| s.info.id == id) {
                    Some(existing.info.port)
                } else if guard.serves.contains_key(&port) {
                    Some(port)
                } else {
                    None
                }
            };
            if let Some(p) = port_to_stop {
                let _ = self.stop(p).await;
            }
        }

        let url = match protocol {
            "tcp" => format!("{internal_hostname}:{port}"),
            _ => format!("https://{internal_hostname}:{port}"),
        };

        let info = ServeInfo {
            id: id.clone(),
            port,
            protocol: protocol.to_string(),
            url: url.clone(),
            status: "active".into(),
        };

        let (stop_tx, stop_rx) = oneshot::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel::<anyhow::Result<()>>();
        let bind = SocketAddr::from((self.mesh_ip, port));
        let routes = self.routes.clone();
        let acl_slot = Arc::new(ArcSwap::from_pointee(acl));
        let acl_for_task = acl_slot.clone();
        let client_tx = self.client_tx.clone();
        let serve_id = id.clone();
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mgr = self.clone();
        let port_c = port;

        if protocol == "tcp" {
            tokio::spawn(async move {
                let result = run_tcp_proxy(
                    bind,
                    local,
                    routes,
                    acl_for_task,
                    serve_id,
                    client_tx,
                    stop_rx,
                    ready_tx,
                )
                .await;
                if let Err(e) = &result {
                    tracing::error!(?e, port = port_c, "serve tcp proxy exited");
                }
                remove_if_generation(&mgr, port_c, generation);
                let _ = finished_tx.send(());
            });
        } else {
            let cert_pem = certificate_pem.context("HTTPS serve requires certificate_pem")?;
            let key_pem = private_key_pem.context("HTTPS serve requires private_key_pem")?;
            let acceptor = build_tls_acceptor(cert_pem, key_pem)?;
            tokio::spawn(async move {
                let result = run_tls_proxy(
                    bind,
                    local,
                    acceptor,
                    routes,
                    acl_for_task,
                    serve_id,
                    client_tx,
                    stop_rx,
                    ready_tx,
                )
                .await;
                if let Err(e) = &result {
                    tracing::error!(?e, port = port_c, "serve tls proxy exited");
                }
                remove_if_generation(&mgr, port_c, generation);
                let _ = finished_tx.send(());
            });
        }

        // Wait for bind success before publishing the serve as active.
        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = finished_rx.await;
                return Err(e);
            }
            Err(_) => {
                let _ = finished_rx.await;
                bail!("serve task exited before bind completed");
            }
        }

        self.inner.lock().serves.insert(
            port,
            ActiveServe {
                info: info.clone(),
                protocol: protocol.to_string(),
                target_addr: local,
                internal_hostname: internal_hostname.to_string(),
                managed,
                acl: acl_slot,
                generation,
                stop: Some(stop_tx),
                finished: Some(finished_rx),
            },
        );

        tracing::info!(%url, port, protocol, managed, "serve active");
        Ok(info)
    }

    pub async fn stop_by_id(&self, id: &str) -> anyhow::Result<ServeInfo> {
        let port = {
            let guard = self.inner.lock();
            guard
                .serves
                .values()
                .find(|s| s.info.id == id)
                .map(|s| s.info.port)
        };
        let Some(port) = port else {
            bail!("no active serve with id {id}");
        };
        self.stop(port).await
    }

    /// Stop dashboard-managed serves whose ids are not in `desired_ids`.
    /// Local/CLI serves are left alone.
    pub async fn reconcile_managed(&self, desired_ids: &[String]) {
        let to_stop: Vec<(String, u16)> = {
            let guard = self.inner.lock();
            guard
                .serves
                .values()
                .filter(|s| s.managed && !desired_ids.iter().any(|id| id == &s.info.id))
                .map(|s| (s.info.id.clone(), s.info.port))
                .collect()
        };
        for (id, port) in to_stop {
            tracing::info!(%id, port, "reconcile: stopping removed managed serve");
            if let Err(e) = self.stop(port).await {
                tracing::warn!(?e, %id, port, "reconcile: stop failed");
            }
        }
    }

    pub async fn stop(&self, port: u16) -> anyhow::Result<ServeInfo> {
        let (finished, mut info) = {
            let mut guard = self.inner.lock();
            let Some(mut active) = guard.serves.remove(&port) else {
                bail!("no active serve on port {port}");
            };
            if let Some(tx) = active.stop.take() {
                let _ = tx.send(());
            }
            let finished = active.finished.take();
            active.info.status = "stopped".into();
            (finished, active.info)
        };

        if let Some(finished) = finished {
            // Ensure the OS has released the listen socket before callers rebind.
            let _ = finished.await;
        }
        info.status = "stopped".into();
        Ok(info)
    }
}

fn remove_if_generation(mgr: &ServeManager, port: u16, generation: u64) {
    let mut guard = mgr.inner.lock();
    if guard
        .serves
        .get(&port)
        .is_some_and(|s| s.generation == generation)
    {
        guard.serves.remove(&port);
    }
}

fn allow_peer(routes: &RoutingTable, acl: &ServeAcl, peer_addr: SocketAddr) -> bool {
    use tunnet_common::policy::Selector;

    match acl.access_mode.as_str() {
        "all_peers" => true,
        "machines" => {
            let ip = match peer_addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => return false,
            };
            let Some(peer) = routes.lookup_ip(&ip) else {
                return false;
            };
            acl.allowed_endpoint_ids.iter().any(|id| {
                Selector::Endpoint(id.clone()).matches_endpoint(
                    &peer.endpoint_hex,
                    &peer.tags,
                    "",
                    Some(ip),
                )
            })
        }
        "tags" => {
            let ip = match peer_addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => return false,
            };
            let Some(peer) = routes.lookup_ip(&ip) else {
                return false;
            };
            acl.allowed_tags.iter().any(|tag| {
                let name = tag.strip_prefix("tag:").unwrap_or(tag);
                Selector::Tag(name.to_string()).matches_endpoint(
                    &peer.endpoint_hex,
                    &peer.tags,
                    "",
                    Some(ip),
                )
            })
        }
        // Fail closed: unknown / empty mode must not grant access.
        _ => false,
    }
}

fn peer_identity(routes: &RoutingTable, peer_addr: SocketAddr) -> (String, Option<String>) {
    let ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return (peer_addr.ip().to_string(), None),
    };
    match routes.lookup_ip(&ip) {
        Some(peer) => {
            let hostname = if peer.hostname.is_empty() {
                None
            } else {
                Some(peer.hostname.clone())
            };
            (peer.endpoint_hex.clone(), hostname)
        }
        None => (peer_addr.ip().to_string(), None),
    }
}

fn report(tx: &Arc<Mutex<Option<mpsc::Sender<ClientMsg>>>>, msg: ClientMsg) {
    if let Some(sender) = tx.lock().as_ref() {
        let _ = sender.try_send(msg);
    }
}

fn build_tls_acceptor(cert_pem: &str, key_pem: &str) -> anyhow::Result<TlsAcceptor> {
    let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certificate PEM")?;
    if certs.is_empty() {
        bail!("no certificates in PEM");
    }

    let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse private key PEM")?
        .context("no private key in PEM")?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_proxy(
    bind: SocketAddr,
    local: SocketAddr,
    routes: RoutingTable,
    acl: Arc<ArcSwap<ServeAcl>>,
    serve_id: String,
    client_tx: Arc<Mutex<Option<mpsc::Sender<ClientMsg>>>>,
    mut stop: oneshot::Receiver<()>,
    ready: oneshot::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let listener = match TcpListener::bind(bind).await {
        Ok(l) => {
            let _ = ready.send(Ok(()));
            l
        }
        Err(e) => {
            let err = anyhow::Error::new(e).context(format!("bind serve TCP {bind}"));
            let _ = ready.send(Err(anyhow::anyhow!("{err:#}")));
            return Err(err);
        }
    };
    tracing::info!(%bind, %local, "serve TCP listening");
    loop {
        tokio::select! {
            _ = &mut stop => {
                tracing::info!(%bind, "serve TCP stopped");
                break;
            }
            accepted = listener.accept() => {
                let (mut inbound, peer) = accepted?;
                if !allow_peer(&routes, &acl.load(), peer) {
                    tracing::debug!(%peer, "serve ACL denied");
                    let _ = inbound.shutdown().await;
                    continue;
                }
                let (peer_endpoint_id, peer_hostname) = peer_identity(&routes, peer);
                let serve_id = serve_id.clone();
                let client_tx = client_tx.clone();
                report(
                    &client_tx,
                    ClientMsg::ServePeerJoined {
                        serve_id: serve_id.clone(),
                        peer_endpoint_id: peer_endpoint_id.clone(),
                        peer_hostname,
                    },
                );
                tokio::spawn(async move {
                    let result = proxy_tcp(inbound, local).await;
                    let (bytes_in, bytes_out) = result.unwrap_or((0, 0));
                    report(
                        &client_tx,
                        ClientMsg::ServePeerLeft {
                            serve_id,
                            peer_endpoint_id,
                            bytes_in,
                            bytes_out,
                        },
                    );
                });
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_tls_proxy(
    bind: SocketAddr,
    local: SocketAddr,
    acceptor: TlsAcceptor,
    routes: RoutingTable,
    acl: Arc<ArcSwap<ServeAcl>>,
    serve_id: String,
    client_tx: Arc<Mutex<Option<mpsc::Sender<ClientMsg>>>>,
    mut stop: oneshot::Receiver<()>,
    ready: oneshot::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let listener = match TcpListener::bind(bind).await {
        Ok(l) => {
            let _ = ready.send(Ok(()));
            l
        }
        Err(e) => {
            let err = anyhow::Error::new(e).context(format!("bind serve TLS {bind}"));
            let _ = ready.send(Err(anyhow::anyhow!("{err:#}")));
            return Err(err);
        }
    };
    tracing::info!(%bind, %local, "serve HTTPS listening");
    loop {
        tokio::select! {
            _ = &mut stop => {
                tracing::info!(%bind, "serve HTTPS stopped");
                break;
            }
            accepted = listener.accept() => {
                let (mut inbound, peer) = accepted?;
                if !allow_peer(&routes, &acl.load(), peer) {
                    tracing::debug!(%peer, "serve ACL denied");
                    let _ = inbound.shutdown().await;
                    continue;
                }
                let (peer_endpoint_id, peer_hostname) = peer_identity(&routes, peer);
                let serve_id = serve_id.clone();
                let client_tx = client_tx.clone();
                let acceptor = acceptor.clone();
                report(
                    &client_tx,
                    ClientMsg::ServePeerJoined {
                        serve_id: serve_id.clone(),
                        peer_endpoint_id: peer_endpoint_id.clone(),
                        peer_hostname,
                    },
                );
                tokio::spawn(async move {
                    let tls = match acceptor.accept(inbound).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(?e, %peer, "TLS handshake failed");
                            report(
                                &client_tx,
                                ClientMsg::ServePeerLeft {
                                    serve_id,
                                    peer_endpoint_id,
                                    bytes_in: 0,
                                    bytes_out: 0,
                                },
                            );
                            return;
                        }
                    };
                    let result = proxy_tls(tls, local).await;
                    let (bytes_in, bytes_out) = result.unwrap_or((0, 0));
                    report(
                        &client_tx,
                        ClientMsg::ServePeerLeft {
                            serve_id,
                            peer_endpoint_id,
                            bytes_in,
                            bytes_out,
                        },
                    );
                });
            }
        }
    }
    Ok(())
}

async fn proxy_tcp(mut inbound: TcpStream, local: SocketAddr) -> anyhow::Result<(u64, u64)> {
    let mut outbound = TcpStream::connect(local).await?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    let (bytes_in, bytes_out) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok((bytes_in, bytes_out))
}

async fn proxy_tls(
    mut inbound: tokio_rustls::server::TlsStream<TcpStream>,
    local: SocketAddr,
) -> anyhow::Result<(u64, u64)> {
    let mut outbound = TcpStream::connect(local).await?;
    let _ = outbound.set_nodelay(true);
    let (bytes_in, bytes_out) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    let _ = outbound.shutdown().await;
    Ok((bytes_in, bytes_out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingTable;
    use std::net::Ipv4Addr;
    use tunnet_common::{DeviceProfile, DnsConfig, PeerEntry};
    use uuid::Uuid;

    fn peer_entry(endpoint: &str, ip: &str) -> PeerEntry {
        PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: endpoint.to_string(),
            hostname: String::new(),
            tags: vec![],
            ssh_host_key: None,
        }
    }

    fn routes_with(peers: &[PeerEntry]) -> RoutingTable {
        let table = RoutingTable::new();
        let self_id = "ff".repeat(32);
        table.replace(
            peers,
            &[],
            &[],
            &[],
            &DeviceProfile::default(),
            &DnsConfig::default(),
            "default",
            Uuid::nil(),
            &self_id,
            1,
        );
        table
    }

    #[test]
    fn allow_peer_all_peers() {
        let routes = RoutingTable::new();
        let acl = ServeAcl {
            access_mode: "all_peers".into(),
            ..Default::default()
        };
        let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 12345));
        assert!(allow_peer(&routes, &acl, peer));
    }

    #[test]
    fn allow_peer_machines_filters_by_endpoint() {
        let desktop = "aa".repeat(32);
        let ctl = "bb".repeat(32);
        let routes = routes_with(&[
            peer_entry(&ctl, "10.7.0.1"),
            peer_entry(&desktop, "10.7.0.2"),
        ]);
        let acl = ServeAcl {
            access_mode: "machines".into(),
            allowed_endpoint_ids: vec![desktop.clone()],
            allowed_tags: Vec::new(),
        };

        let from_ctl = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 1));
        let from_desktop = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 1));
        assert!(!allow_peer(&routes, &acl, from_ctl));
        assert!(allow_peer(&routes, &acl, from_desktop));
    }

    #[test]
    fn allow_peer_machines_empty_denies_all() {
        let routes = routes_with(&[peer_entry(&"cc".repeat(32), "10.7.0.1")]);
        let acl = ServeAcl {
            access_mode: "machines".into(),
            allowed_endpoint_ids: Vec::new(),
            allowed_tags: Vec::new(),
        };
        let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 1));
        assert!(!allow_peer(&routes, &acl, peer));
    }

    #[test]
    fn allow_peer_unknown_mode_denies() {
        let routes = RoutingTable::new();
        let acl = ServeAcl {
            access_mode: "bogus".into(),
            ..Default::default()
        };
        let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 1));
        assert!(!allow_peer(&routes, &acl, peer));
    }

    #[tokio::test]
    async fn access_change_updates_acl_without_rebind() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mgr = ServeManager::new(Ipv4Addr::LOCALHOST, RoutingTable::new());
        let info = mgr
            .start(
                "serve-1".into(),
                port,
                "tcp",
                "host.default.tunnet",
                None,
                None,
                ServeAcl {
                    access_mode: "all_peers".into(),
                    ..Default::default()
                },
                Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
                true,
            )
            .await
            .unwrap();
        assert_eq!(info.port, port);

        let generation_before = {
            let guard = mgr.inner.lock();
            guard.serves.get(&port).unwrap().generation
        };

        let updated = mgr
            .start(
                "serve-1".into(),
                port,
                "tcp",
                "host.default.tunnet",
                None,
                None,
                ServeAcl {
                    access_mode: "machines".into(),
                    allowed_endpoint_ids: vec!["aa".repeat(32)],
                    allowed_tags: Vec::new(),
                },
                Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
                true,
            )
            .await
            .unwrap();
        assert_eq!(updated.id, "serve-1");

        {
            let guard = mgr.inner.lock();
            let active = guard.serves.get(&port).unwrap();
            assert_eq!(
                active.generation, generation_before,
                "must not restart proxy"
            );
            assert_eq!(active.acl.load().access_mode, "machines");
            assert_eq!(active.acl.load().allowed_endpoint_ids.len(), 1);
            assert!(active.managed);
        }

        mgr.stop(port).await.unwrap();
    }

    #[tokio::test]
    async fn reconcile_stops_removed_managed_serves() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mgr = ServeManager::new(Ipv4Addr::LOCALHOST, RoutingTable::new());
        mgr.start(
            "managed-1".into(),
            port,
            "tcp",
            "host.default.tunnet",
            None,
            None,
            ServeAcl::default(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
            true,
        )
        .await
        .unwrap();

        mgr.reconcile_managed(&[]).await;
        assert!(
            mgr.list().is_empty(),
            "managed serve must stop when omitted"
        );
    }

    #[tokio::test]
    async fn stop_then_start_rebinds_same_port() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mgr = ServeManager::new(Ipv4Addr::LOCALHOST, RoutingTable::new());
        mgr.start(
            "serve-2".into(),
            port,
            "tcp",
            "host.default.tunnet",
            None,
            None,
            ServeAcl::default(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
            true,
        )
        .await
        .unwrap();

        mgr.stop(port).await.unwrap();

        mgr.start(
            "serve-2".into(),
            port,
            "tcp",
            "host.default.tunnet",
            None,
            None,
            ServeAcl {
                access_mode: "machines".into(),
                allowed_endpoint_ids: Vec::new(),
                allowed_tags: Vec::new(),
            },
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
            true,
        )
        .await
        .expect("rebind after awaited stop must succeed");

        mgr.stop(port).await.unwrap();
    }
}
