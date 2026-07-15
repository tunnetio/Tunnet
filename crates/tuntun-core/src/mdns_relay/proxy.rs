use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::types::LocalService;

struct ActiveProxy {
    lan_ip: Ipv4Addr,
    stop: Option<oneshot::Sender<()>>,
}

/// Listens on mesh_ip:port and splices TCP to lan_ip:port.
#[derive(Clone)]
pub struct ServiceProxy {
    mesh_ip: Ipv4Addr,
    inner: Arc<Mutex<HashMap<u16, ActiveProxy>>>,
}

impl ServiceProxy {
    pub fn new(mesh_ip: Ipv4Addr) -> Self {
        Self {
            mesh_ip,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn ensure(&self, svc: &LocalService) {
        let port = svc.port;
        let lan_ip = svc.lan_ip;
        {
            let guard = self.inner.lock();
            if let Some(existing) = guard.get(&port)
                && existing.lan_ip == lan_ip
            {
                return;
            }
        }
        self.stop(port);
        if let Err(e) = self.start(port, lan_ip) {
            tracing::warn!(port, %lan_ip, ?e, "service proxy start failed");
        }
    }

    pub fn remove_for(&self, svc: &LocalService) {
        let mut guard = self.inner.lock();
        if let Some(active) = guard.get(&svc.port)
            && active.lan_ip == svc.lan_ip
            && let Some(active) = guard.remove(&svc.port)
            && let Some(stop) = active.stop
        {
            let _ = stop.send(());
        }
    }

    pub fn stop(&self, port: u16) {
        if let Some(active) = self.inner.lock().remove(&port)
            && let Some(stop) = active.stop
        {
            let _ = stop.send(());
        }
    }

    fn start(&self, port: u16, lan_ip: Ipv4Addr) -> anyhow::Result<()> {
        let bind = SocketAddr::from((self.mesh_ip, port));
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let mesh_ip = self.mesh_ip;

        let rt_handle = tokio::runtime::Handle::current();
        rt_handle.spawn(async move {
            let listener = match TcpListener::bind(bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(%bind, ?e, "service proxy bind failed");
                    return;
                }
            };
            tracing::info!(%bind, %lan_ip, "service proxy listening");
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        tracing::debug!(%bind, "service proxy stopped");
                        break;
                    }
                    acc = listener.accept() => {
                        match acc {
                            Ok((inbound, peer)) => {
                                tokio::spawn(async move {
                                    if let Err(e) = proxy_one(inbound, lan_ip, port).await {
                                        tracing::debug!(%peer, ?e, "service proxy session ended");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(%bind, ?e, "service proxy accept error");
                                break;
                            }
                        }
                    }
                }
            }
        });

        self.inner.lock().insert(
            port,
            ActiveProxy {
                lan_ip,
                stop: Some(stop_tx),
            },
        );
        let _ = mesh_ip;
        Ok(())
    }
}

async fn proxy_one(mut inbound: TcpStream, lan_ip: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    let target = SocketAddr::from((lan_ip, port));
    let mut outbound = TcpStream::connect(target).await?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(_) => {}
        Err(e) => tracing::trace!(?e, "proxy splice ended"),
    }
    let _ = inbound.shutdown().await;
    let _ = outbound.shutdown().await;
    Ok(())
}
