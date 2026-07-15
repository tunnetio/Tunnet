//! Cross-LAN mDNS/DNS-SD service relay over the TunTun mesh.
//!
//! One shared [`iroh_gossip::net::Gossip`] instance (from Direct docs or Managed
//! agent Gossip) carries structured [`types::ServiceRecord`]s. Local LAN services
//! are discovered via `mdns-sd`, published to peers, advertised locally with the
//! origin peer's mesh IP, and TCP-proxied on the origin agent.

mod gossip;
mod proxy;
mod responder;
mod scanner;
pub mod types;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use mdns_sd::ServiceDaemon;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::routing::RoutingTable;

use proxy::ServiceProxy;
use responder::Responder;
use scanner::{AdvertisedSet, DEFAULT_TTL, ScanEvent, spawn_scanner};
use types::{EventType, LocalServiceTable, RemoteServiceTable, ServiceRecord};

pub struct SpawnConfig {
    pub gossip: Gossip,
    pub topic_hex: String,
    pub bootstrap: Vec<EndpointId>,
    pub mesh_ip: Ipv4Addr,
    pub endpoint_id: String,
    pub routes: RoutingTable,
}

/// Start the service-relay subsystem. Returns a join handle for the orchestrator.
pub fn spawn(cfg: SpawnConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(cfg).await {
            tracing::error!(?e, "mDNS service relay exited");
        }
    })
}

async fn run(cfg: SpawnConfig) -> anyhow::Result<()> {
    let daemon = ServiceDaemon::new().map_err(|e| anyhow::anyhow!("ServiceDaemon: {e}"))?;
    tracing::info!(mesh = %cfg.mesh_ip, "mDNS service relay starting");

    let advertised: AdvertisedSet = Arc::new(Mutex::new(HashSet::new()));
    let (scan_tx, mut scan_rx) = mpsc::unbounded_channel::<ScanEvent>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<ServiceRecord>();
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<ServiceRecord>();

    spawn_scanner(daemon.clone(), cfg.mesh_ip, advertised.clone(), scan_tx)?;

    let responder = Arc::new(Responder::new(daemon.clone(), advertised.clone()));
    let proxy = ServiceProxy::new(cfg.mesh_ip);

    let gossip_task = {
        let gossip = cfg.gossip.clone();
        let topic = cfg.topic_hex.clone();
        let bootstrap = cfg.bootstrap.clone();
        let routes = cfg.routes.clone();
        let self_id = cfg.endpoint_id.clone();
        tokio::spawn(async move {
            if let Err(e) =
                gossip::run_gossip(gossip, topic, bootstrap, routes, self_id, out_rx, in_tx).await
            {
                tracing::warn!(?e, "mdns-relay gossip stopped");
            }
        })
    };

    let mut local = LocalServiceTable::default();
    let mut remote = RemoteServiceTable::default();
    let mut expire = tokio::time::interval(Duration::from_secs(30));
    tokio::pin!(gossip_task);

    loop {
        tokio::select! {
            ev = scan_rx.recv() => {
                let Some(ev) = ev else { break; };
                match ev {
                    ScanEvent::Upsert(svc) => {
                        if let Some(event) = local.upsert(svc.clone()) {
                            let record = svc.record(
                                cfg.mesh_ip,
                                &cfg.endpoint_id,
                                event,
                                DEFAULT_TTL,
                            );
                            let _ = out_tx.send(record);
                            proxy.ensure(&svc);
                        }
                    }
                    ScanEvent::Remove { fullname } => {
                        if let Some(svc) = local.remove(&fullname) {
                            proxy.remove_for(&svc);
                            let record = svc.record(
                                cfg.mesh_ip,
                                &cfg.endpoint_id,
                                EventType::Removed,
                                0,
                            );
                            let _ = out_tx.send(record);
                        }
                    }
                }
            }
            rec = in_rx.recv() => {
                let Some(record) = rec else { break; };
                if let Some(ev) = remote.apply(record.clone()) {
                    tracing::info!(
                        fullname = %record.fullname,
                        peer = %record.origin_peer_ip,
                        ?ev,
                        "remote ServiceRecord applied"
                    );
                    let mut r = record;
                    r.event_type = ev;
                    responder.apply(&r);
                }
            }
            _ = expire.tick() => {
                for expired in remote.expire() {
                    responder.apply(&expired);
                }
            }
            _ = &mut gossip_task => {
                tracing::warn!("mdns-relay gossip task ended");
                break;
            }
        }
    }

    let _ = daemon.shutdown();
    Ok(())
}
