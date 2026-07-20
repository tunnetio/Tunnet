use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use tunnet_audit::AuditEmitter;
use tunnet_common::license::Entitlements;

use crate::config::Args;
use crate::pg_notify;
use crate::posture::PostureGraceMap;
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
    pub posture_grace: PostureGraceMap,
    pub audit: AuditEmitter,
    #[allow(dead_code)] // Used when ClickHouse / enterprise streams are enabled.
    pub entitlements: Entitlements,
}

impl AppState {
    pub fn new(
        args: Args,
        pool: PgPool,
        policy_key: SigningKey,
        service_auth: ServiceAuth,
        audit: AuditEmitter,
        entitlements: Entitlements,
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
            posture_grace: crate::posture::grace_map(),
            audit,
            entitlements,
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

    /// Delete expired / consumed short-lived auth material.
    pub async fn purge_expired_ephemera(self: &Arc<Self>) -> anyhow::Result<()> {
        let challenges = sqlx::query(
            "DELETE FROM ssh_auth_challenges \
             WHERE expires_at < now() \
                OR (status <> 'pending' AND created_at < now() - interval '7 days') \
                OR (proof_expires_at IS NOT NULL AND proof_expires_at < now() \
                    AND proof_consumed_at IS NOT NULL)",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        let enrollment = sqlx::query(
            "DELETE FROM enrollment_tokens \
             WHERE expires_at < now() OR used_at IS NOT NULL",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        let relay_tokens = sqlx::query(
            "DELETE FROM relay_registration_tokens \
             WHERE expires_at < now() OR used_at IS NOT NULL",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        if challenges + enrollment + relay_tokens > 0 {
            tracing::info!(
                challenges,
                enrollment,
                relay_tokens,
                "purged expired ephemeral tokens"
            );
        }
        Ok(())
    }
}

pub type SharedState = Arc<AppState>;
