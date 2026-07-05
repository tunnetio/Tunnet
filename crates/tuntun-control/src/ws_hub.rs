//! Fan-out for server → agent WebSocket pushes.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tuntun_common::ws::ServerMsg;
use uuid::Uuid;

use crate::metrics::Metrics;

#[derive(Clone)]
pub struct WsHub {
    inner: Arc<Inner>,
    metrics: Metrics,
}

struct Inner {
    subs: DashMap<String, mpsc::Sender<ServerMsg>>,
    by_network: DashMap<Uuid, dashmap::DashSet<String>>,
}

impl WsHub {
    pub fn new(metrics: Metrics) -> Self {
        Self {
            inner: Arc::new(Inner {
                subs: DashMap::new(),
                by_network: DashMap::new(),
            }),
            metrics,
        }
    }

    pub fn register(
        &self,
        endpoint_id: String,
        network_ids: Vec<Uuid>,
    ) -> mpsc::Receiver<ServerMsg> {
        let (tx, rx) = mpsc::channel(64);
        self.inner.subs.insert(endpoint_id.clone(), tx);
        for network_id in network_ids {
            self.inner
                .by_network
                .entry(network_id)
                .or_default()
                .insert(endpoint_id.clone());
        }
        self.metrics.ws_connected.inc();
        self.metrics
            .devices_online
            .set(self.inner.subs.len() as i64);
        rx
    }

    pub fn unregister(&self, endpoint_id: &str, network_ids: &[Uuid]) {
        self.inner.subs.remove(endpoint_id);
        for network_id in network_ids {
            if let Some(set) = self.inner.by_network.get(network_id) {
                set.remove(endpoint_id);
            }
        }
        self.metrics.ws_connected.dec();
        self.metrics
            .devices_online
            .set(self.inner.subs.len() as i64);
    }

    pub fn connection_count(&self) -> i64 {
        self.inner.subs.len() as i64
    }

    pub async fn push_to(&self, endpoint_id: &str, msg: ServerMsg) {
        if let Some(tx) = self.inner.subs.get(endpoint_id) {
            let _ = tx.try_send(msg);
        }
    }

    pub async fn notify_network_changed(&self, network_id: Uuid) {
        let Some(set) = self.inner.by_network.get(&network_id) else {
            return;
        };
        let ids: Vec<String> = set.iter().map(|e| e.clone()).collect();
        drop(set);
        for id in ids {
            self.push_to(&id, ServerMsg::Ping { nonce: 0 }).await;
        }
    }
}
