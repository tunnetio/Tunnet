//! Shared daemon state for the Local Management API.

use std::sync::Arc;
use std::time::Instant;

use tunnet_common::local_api::LocalEvent;

use crate::node::CoreNode;
use crate::send::SendManager;
use crate::serve::ServeManager;
use crate::tunnel::TunnelManager;

use super::bootstrap::BootstrapOps;
use super::dataplane::DataPlaneControl;

/// Live agent state shared with the Local Management API server.
pub struct LocalApiState {
    pub node: CoreNode,
    pub hostname: String,
    pub agent_version: String,
    pub started_at: Instant,
    pub dns_upstream: Vec<String>,
    pub dnssec: bool,
    pub resolver_endpoint: String,
    pub peer_dns_active: Arc<std::sync::atomic::AtomicBool>,
    pub peer_rtt: Arc<dashmap::DashMap<String, f64>>,
    pub serves: ServeManager,
    pub tunnels: TunnelManager,
    pub send: SendManager,
    pub data_plane: Arc<dyn DataPlaneControl>,
    pub bootstrap: Arc<dyn BootstrapOps>,
    pub events: tokio::sync::broadcast::Sender<LocalEvent>,
}

impl LocalApiState {
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn emit(&self, event: LocalEvent) {
        let _ = self.events.send(event);
    }
}
