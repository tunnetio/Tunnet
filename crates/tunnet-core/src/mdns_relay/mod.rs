//! Cross-LAN mDNS/DNS-SD service relay over the Tunnet mesh.
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
use tokio_util::task::AbortOnDropHandle;

use crate::forward::{ForwardingStore, PolicyEngine};
use crate::identity::AgentIdentity;
use uuid::Uuid;

use proxy::ServiceProxy;
use responder::Responder;
use scanner::{AdvertisedSet, DEFAULT_TTL, ScanEvent, spawn_scanner};
use types::{EventType, LocalServiceTable, RemoteServiceTable, ServiceRecord};

pub struct SpawnConfig {
    pub gossip: Gossip,
    pub network: Uuid,
    pub bootstrap: Vec<EndpointId>,
    pub mesh_ip: Ipv4Addr,
    pub endpoint_id: String,
    pub forwarding: ForwardingStore,
    pub policy: PolicyEngine,
    pub identity: AgentIdentity,
    pub socket_config: [Option<iroh::endpoint::SocketConfig>; 2],
    pub tcp_config: [Option<iroh::endpoint::TcpSocketConfig>; 2],
    pub cancel: tokio_util::sync::CancellationToken,
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
    let daemon = ServiceDaemon::new_with_socket_config(cfg.socket_config)
        .map_err(|e| anyhow::anyhow!("ServiceDaemon: {e}"))?;
    struct DaemonShutdown(ServiceDaemon);
    impl Drop for DaemonShutdown {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _shutdown = DaemonShutdown(daemon.clone());
    tracing::info!(mesh = %cfg.mesh_ip, "mDNS service relay starting");

    let advertised: AdvertisedSet = Arc::new(Mutex::new(HashSet::new()));
    let (scan_tx, mut scan_rx) = mpsc::channel::<ScanEvent>(256);
    let (out_tx, out_rx) = mpsc::channel::<ServiceRecord>(256);
    let (in_tx, mut in_rx) = mpsc::channel::<ServiceRecord>(256);

    let mut scanner = AbortOnDropHandle::new(spawn_scanner(
        daemon.clone(),
        cfg.mesh_ip,
        advertised.clone(),
        scan_tx,
    )?);

    let responder = Arc::new(Responder::new(daemon.clone(), advertised.clone()));
    let mut proxy = ServiceProxy::new(
        cfg.mesh_ip,
        cfg.network,
        cfg.forwarding.clone(),
        cfg.policy.clone(),
        cfg.tcp_config,
    );

    let gossip_task = {
        let gossip = cfg.gossip.clone();
        let network = cfg.network;
        let bootstrap = cfg.bootstrap.clone();
        let forwarding = cfg.forwarding.clone();
        let identity = cfg.identity.clone();
        tokio::spawn(async move {
            if let Err(e) = gossip::run_gossip(
                gossip, network, bootstrap, forwarding, identity, out_rx, in_tx,
            )
            .await
            {
                tracing::warn!(?e, "mdns-relay gossip stopped");
            }
        })
    };

    let mut local = LocalServiceTable::default();
    let mut remote = RemoteServiceTable::default();
    let mut expire = tokio::time::interval(Duration::from_secs(1));
    let mut changes = cfg.forwarding.subscribe_changes();
    #[cfg(feature = "direct")]
    let mut auth_changes = cfg
        .forwarding
        .load()
        .direct_auth
        .as_ref()
        .map(|auth| auth.subscribe_changes());
    let mut gossip_task = AbortOnDropHandle::new(gossip_task);

    loop {
        tokio::select! {
            _ = cfg.cancel.cancelled() => break,
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
                            tokio::select! {
                                _ = cfg.cancel.cancelled() => break,
                                _ = out_tx.send(record) => {}
                            }
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
                            tokio::select! {
                                _ = cfg.cancel.cancelled() => break,
                                _ = out_tx.send(record) => {}
                            }
                        }
                    }
                }
            }
            rec = in_rx.recv() => {
                let Some(record) = rec else { break; };
                if !gossip::record_authorized(&cfg.forwarding.load(), cfg.network, &record) { continue; }
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
            _ = changes.changed() => {
                for removed in remote.retain(|record| gossip::record_authorized(&cfg.forwarding.load(), cfg.network, record)) {
                    responder.apply(&removed);
                }
            }
            _ = async {
                #[cfg(feature = "direct")]
                if let Some(changes) = &mut auth_changes { let _ = changes.changed().await; return; }
                std::future::pending::<()>().await;
            } => {
                for removed in remote.retain(|record| gossip::record_authorized(&cfg.forwarding.load(), cfg.network, record)) {
                    responder.apply(&removed);
                }
            }
            _ = expire.tick() => {
                for removed in remote.retain(|record| gossip::record_authorized(&cfg.forwarding.load(), cfg.network, record)) {
                    responder.apply(&removed);
                }
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

    scanner.abort();
    let _ = (&mut scanner).await;
    if !gossip_task.is_finished() {
        gossip_task.abort();
        let _ = (&mut gossip_task).await;
    }
    proxy.shutdown().await;
    daemon.abort();
    while !daemon.is_finished() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}
