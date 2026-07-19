//! Fan-out for server → agent WebSocket pushes.

use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tunnet_common::ws::ServerMsg;
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
    by_org: DashMap<String, dashmap::DashSet<String>>,
}

impl WsHub {
    pub fn new(metrics: Metrics) -> Self {
        Self {
            inner: Arc::new(Inner {
                subs: DashMap::new(),
                by_network: DashMap::new(),
                by_org: DashMap::new(),
            }),
            metrics,
        }
    }

    pub fn register(
        &self,
        endpoint_id: String,
        organization_id: String,
        network_ids: Vec<Uuid>,
    ) -> mpsc::Receiver<ServerMsg> {
        let (tx, rx) = mpsc::channel(64);
        self.inner.subs.insert(endpoint_id.clone(), tx);
        self.inner
            .by_org
            .entry(organization_id)
            .or_default()
            .insert(endpoint_id.clone());
        for network_id in network_ids {
            self.inner
                .by_network
                .entry(network_id)
                .or_default()
                .insert(endpoint_id.clone());
        }
        self.metrics.ws_connected_inc();
        self.metrics
            .devices_online_set(self.inner.subs.len() as i64);
        rx
    }

    pub fn unregister(&self, endpoint_id: &str, organization_id: &str, network_ids: &[Uuid]) {
        self.inner.subs.remove(endpoint_id);
        if let Some(set) = self.inner.by_org.get(organization_id) {
            set.remove(endpoint_id);
        }
        for network_id in network_ids {
            if let Some(set) = self.inner.by_network.get(network_id) {
                set.remove(endpoint_id);
            }
        }
        self.metrics.ws_connected_dec();
        self.metrics
            .devices_online_set(self.inner.subs.len() as i64);
    }

    pub fn connection_count(&self) -> i64 {
        self.inner.subs.len() as i64
    }

    pub async fn push_to(&self, endpoint_id: &str, msg: ServerMsg) {
        if let Some(tx) = self.inner.subs.get(endpoint_id) {
            let _ = tx.try_send(msg);
        }
    }

    /// Broadcast a peer-joined delta to other agents on the network (skips `joined_endpoint_id`).
    pub async fn notify_peer_joined(
        &self,
        network_id: Uuid,
        joined_endpoint_id: &str,
        peer: tunnet_common::PeerEntry,
        version: u64,
    ) {
        let Some(set) = self.inner.by_network.get(&network_id) else {
            return;
        };
        let ids: Vec<String> = set
            .iter()
            .filter(|e| e.as_str() != joined_endpoint_id)
            .map(|e| e.clone())
            .collect();
        drop(set);

        tracing::info!(
            %network_id,
            peer = %joined_endpoint_id,
            agents = ids.len(),
            "pushing peer-joined delta"
        );

        let msg = ServerMsg::Delta(tunnet_common::SnapshotDelta {
            added: vec![peer],
            removed: vec![],
            version,
        });
        for endpoint_id in ids {
            self.push_to(&endpoint_id, msg.clone()).await;
        }
    }

    /// Broadcast a peer-left delta to other agents on the network.
    pub async fn notify_peer_left(&self, network_id: Uuid, left_endpoint_id: &str, version: u64) {
        let Some(set) = self.inner.by_network.get(&network_id) else {
            return;
        };
        let ids: Vec<String> = set
            .iter()
            .filter(|e| e.as_str() != left_endpoint_id)
            .map(|e| e.clone())
            .collect();
        drop(set);

        tracing::info!(
            %network_id,
            peer = %left_endpoint_id,
            agents = ids.len(),
            "pushing peer-left delta"
        );

        let msg = ServerMsg::Delta(tunnet_common::SnapshotDelta {
            added: vec![],
            removed: vec![left_endpoint_id.to_string()],
            version,
        });
        for endpoint_id in ids {
            self.push_to(&endpoint_id, msg.clone()).await;
        }
    }

    /// Kick a connected agent: send ForceReenroll and drop the subscription.
    pub async fn disconnect(&self, endpoint_id: &str, reason: &str) {
        self.push_to(
            endpoint_id,
            ServerMsg::ForceReenroll {
                reason: reason.to_string(),
            },
        )
        .await;
        if self.inner.subs.remove(endpoint_id).is_some() {
            for entry in self.inner.by_network.iter() {
                entry.value().remove(endpoint_id);
            }
            for entry in self.inner.by_org.iter() {
                entry.value().remove(endpoint_id);
            }
            self.metrics.ws_connected_dec();
            self.metrics
                .devices_online_set(self.inner.subs.len() as i64);
        }
    }

    pub async fn notify_network_changed(
        &self,
        network_id: Uuid,
        pool: &PgPool,
        policy_key: &SigningKey,
    ) {
        let Some(set) = self.inner.by_network.get(&network_id) else {
            return;
        };
        let ids: Vec<String> = set.iter().map(|e| e.clone()).collect();
        drop(set);

        tracing::info!(%network_id, agents = ids.len(), "pushing snapshots after network change");

        for endpoint_id in ids {
            match crate::snapshot::build_endpoint_snapshot(pool, policy_key, &endpoint_id).await {
                Ok(snap) => {
                    self.push_to(&endpoint_id, ServerMsg::Snapshot(Box::new(snap)))
                        .await;
                }
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        %endpoint_id,
                        %network_id,
                        "failed to build snapshot for network-change push"
                    );
                }
            }
        }
    }

    pub async fn notify_org_changed(
        &self,
        organization_id: &str,
        pool: &PgPool,
        policy_key: &SigningKey,
    ) {
        let Some(set) = self.inner.by_org.get(organization_id) else {
            return;
        };
        let ids: Vec<String> = set.iter().map(|e| e.clone()).collect();
        drop(set);

        tracing::info!(
            %organization_id,
            agents = ids.len(),
            "pushing snapshots after org change"
        );

        for endpoint_id in ids {
            match crate::snapshot::build_endpoint_snapshot(pool, policy_key, &endpoint_id).await {
                Ok(snap) => {
                    self.push_to(&endpoint_id, ServerMsg::Snapshot(Box::new(snap)))
                        .await;
                }
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        %endpoint_id,
                        %organization_id,
                        "failed to build snapshot for org-change push"
                    );
                }
            }
        }
    }
}
