use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use mdns_sd::{ServiceDaemon, ServiceEvent};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use super::types::{LocalService, is_mesh_ipv4};

const META_QUERY: &str = "_services._dns-sd._udp.local.";
pub const DEFAULT_TTL: u32 = 120;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Upsert(LocalService),
    Remove { fullname: String },
}

/// Fullnames we registered as the mesh responder — ignored by the scanner.
pub type AdvertisedSet = Arc<Mutex<HashSet<String>>>;

pub fn spawn_scanner(
    daemon: ServiceDaemon,
    mesh_ip: Ipv4Addr,
    advertised: AdvertisedSet,
    tx: mpsc::UnboundedSender<ScanEvent>,
) -> anyhow::Result<()> {
    let meta_rx = daemon
        .browse(META_QUERY)
        .map_err(|e| anyhow::anyhow!("mdns browse meta: {e}"))?;

    let browsing: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    tokio::spawn(async move {
        loop {
            match meta_rx.recv_async().await {
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
                    spawn_type_browser(daemon.clone(), ty, mesh_ip, advertised.clone(), tx.clone());
                }
                Ok(other) => {
                    tracing::trace!(?other, "mdns meta event");
                }
                Err(_) => {
                    tracing::debug!("mdns meta browse ended");
                    break;
                }
            }
        }
    });

    Ok(())
}

fn spawn_type_browser(
    daemon: ServiceDaemon,
    service_type: String,
    mesh_ip: Ipv4Addr,
    advertised: AdvertisedSet,
    tx: mpsc::UnboundedSender<ScanEvent>,
) {
    let Ok(rx) = daemon.browse(&service_type) else {
        tracing::warn!(%service_type, "mdns browse service type failed");
        return;
    };
    tracing::debug!(%service_type, "browsing mDNS service type");
    tokio::spawn(async move {
        while let Ok(ev) = rx.recv_async().await {
            handle_service_event(ev, mesh_ip, &advertised, &tx);
        }
    });
}

fn handle_service_event(
    event: ServiceEvent,
    mesh_ip: Ipv4Addr,
    advertised: &AdvertisedSet,
    tx: &mpsc::UnboundedSender<ScanEvent>,
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
            let _ = tx.send(ScanEvent::Upsert(svc));
        }
        ServiceEvent::ServiceRemoved(_ty, fullname) => {
            if advertised.lock().contains(&fullname.to_lowercase()) {
                return;
            }
            tracing::info!(%fullname, "mDNS service removed");
            let _ = tx.send(ScanEvent::Remove { fullname });
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
