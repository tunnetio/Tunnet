use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use mdns_sd::{ServiceDaemon, ServiceEvent};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use super::types::{LocalService, is_mesh_ipv4};

const META_QUERY: &str = "_services._dns-sd._udp.local.";
pub const DEFAULT_TTL: u32 = 120;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Upsert(LocalService),
    Remove { fullname: String },
}

pub type AdvertisedSet = Arc<Mutex<HashSet<String>>>;

pub fn spawn_scanner(
    daemon: ServiceDaemon,
    mesh_ip: Ipv4Addr,
    advertised: AdvertisedSet,
    tx: mpsc::Sender<ScanEvent>,
) -> anyhow::Result<JoinHandle<()>> {
    let mut meta_rx = daemon
        .browse(META_QUERY)
        .map_err(|e| anyhow::anyhow!("mdns browse meta: {e}"))?;

    let browsing: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    Ok(tokio::spawn(async move {
        let mut browsers = JoinSet::new();
        loop {
            let event = tokio::select! {
                event = meta_rx.recv_async() => event,
                _ = browsers.join_next(), if !browsers.is_empty() => { continue; }
            };
            match event {
                Ok(ServiceEvent::ServiceFound(_meta, service_type)) => {
                    let ty = normalize_type(&service_type);
                    if ty == META_QUERY || !ty.contains("._") {
                        continue;
                    }
                    {
                        let mut guard = browsing.lock();
                        if !guard.insert(ty.clone()) {
                            continue;
                        }
                    }
                    if browsing.lock().len() > 64 {
                        browsing.lock().remove(&ty);
                        continue;
                    }
                    let daemon = daemon.clone();
                    let advertised = advertised.clone();
                    let tx = tx.clone();
                    let browsing = browsing.clone();
                    browsers.spawn(async move {
                        browse_type(daemon, ty.clone(), mesh_ip, advertised, tx).await;
                        browsing.lock().remove(&ty);
                    });
                }
                Ok(other) => {
                    tracing::trace!(?other, "mdns meta event");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "mdns meta browse ended");
                    match renew_browse(&daemon, META_QUERY).await {
                        Ok(receiver) => meta_rx = receiver,
                        Err(_) => break,
                    }
                }
            }
        }
    }))
}

async fn renew_browse(
    daemon: &ServiceDaemon,
    service_type: &str,
) -> mdns_sd::Result<mdns_sd::Receiver<ServiceEvent>> {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        match daemon.browse(service_type) {
            Err(mdns_sd::Error::Again) => continue,
            result => return result,
        }
    }
}

async fn browse_type(
    daemon: ServiceDaemon,
    service_type: String,
    mesh_ip: Ipv4Addr,
    advertised: AdvertisedSet,
    tx: mpsc::Sender<ScanEvent>,
) {
    let Ok(mut rx) = renew_browse(&daemon, &service_type).await else {
        tracing::warn!(%service_type, "mdns browse service type failed");
        return;
    };
    tracing::debug!(%service_type, "browsing mDNS service type");
    loop {
        tokio::select! {
            _ = tx.closed() => break,
            event = rx.recv_async() => match event {
                Ok(event) => handle_service_event(event, mesh_ip, &advertised, &tx).await,
                Err(_) => match renew_browse(&daemon, &service_type).await {
                    Ok(receiver) => rx = receiver,
                    Err(_) => break,
                },
            },
        }
    }
    let _ = daemon.stop_browse(&service_type);
    tracing::debug!(%service_type, "mdns service-type browse ended");
}

async fn handle_service_event(
    event: ServiceEvent,
    mesh_ip: Ipv4Addr,
    advertised: &AdvertisedSet,
    tx: &mpsc::Sender<ScanEvent>,
) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            let fullname = info.get_fullname().to_string();
            if advertised.lock().contains(&fullname.to_lowercase()) {
                return;
            }
            let addrs = info.get_addresses_v4();
            if addrs.iter().any(|a| *a == mesh_ip || is_mesh_ipv4(*a)) {
                tracing::trace!(%fullname, "skip mesh/relayed mDNS service");
                return;
            }
            let Some(lan_ip) = addrs.into_iter().next() else {
                return;
            };
            let service_type = info.ty_domain.clone();
            let instance_name = super::types::instance_name_from_fullname(&fullname, &service_type);
            let mut txt = HashMap::new();
            for prop in info.get_properties().iter() {
                txt.insert(prop.key().to_string(), prop.val_str().to_string());
            }
            let svc = LocalService {
                service_type,
                instance_name,
                fullname,
                lan_ip,
                port: info.get_port(),
                txt_records: txt,
                host: info.get_hostname().to_string(),
            };
            tracing::info!(
                fullname = %svc.fullname,
                lan = %svc.lan_ip,
                port = svc.port,
                "mDNS service discovered"
            );
            let _ = tx.send(ScanEvent::Upsert(svc)).await;
        }
        ServiceEvent::ServiceRemoved(_ty, fullname) => {
            if advertised.lock().contains(&fullname.to_lowercase()) {
                return;
            }
            tracing::info!(%fullname, "mDNS service removed");
            let _ = tx.send(ScanEvent::Remove { fullname }).await;
        }
        _ => {}
    }
}

fn normalize_type(s: &str) -> String {
    let mut t = s.trim().to_lowercase();
    if !t.ends_with('.') {
        t.push('.');
    }
    t
}
