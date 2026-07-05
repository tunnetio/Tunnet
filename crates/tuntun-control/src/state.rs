use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;

use crate::config::Args;
use crate::pg_notify;
use crate::service_auth::ServiceAuth;
use crate::ws_hub::WsHub;

pub struct AppState {
    pub args: Args,
    pub pool: PgPool,
    pub policy_key: SigningKey,
    pub ws_hub: WsHub,
    pub metrics: crate::metrics::Metrics,
    pub service_auth: ServiceAuth,
    pub listen_connected: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(
        args: Args,
        pool: PgPool,
        policy_key: SigningKey,
        service_auth: ServiceAuth,
    ) -> Self {
        let metrics = crate::metrics::Metrics::new().expect("metrics registration");
        Self {
            ws_hub: WsHub::new(metrics.clone()),
            args,
            pool,
            policy_key,
            metrics,
            service_auth,
            listen_connected: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn evict_stale_devices(self: &Arc<Self>) -> anyhow::Result<()> {
        let ttl = self.args.stale_ttl_secs as i64;
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT network_id FROM network_memberships nm \
             JOIN devices d ON d.endpoint_id = nm.endpoint_id \
             WHERE d.last_seen < now() - make_interval(secs => $1)",
        )
        .bind(ttl as f64)
        .fetch_all(&self.pool)
        .await?;

        for (network_id,) in rows {
            sqlx::query("UPDATE networks SET version = version + 1 WHERE id = $1")
                .bind(network_id)
                .execute(&self.pool)
                .await?;
            pg_notify::emit_network_changed(&self.pool, network_id).await?;
        }
        Ok(())
    }
}

pub type SharedState = Arc<AppState>;
