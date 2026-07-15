use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgListener;
use uuid::Uuid;

use crate::ws_hub::WsHub;

pub const CHANNEL: &str = "tuntun:network_changed";
pub const ORG_CHANNEL: &str = "tuntun:org_changed";

pub async fn emit_network_changed(pool: &PgPool, network_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(network_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn emit_org_changed(pool: &PgPool, organization_id: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(ORG_CHANNEL)
        .bind(organization_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn run_listener(
    database_url: &str,
    pool: PgPool,
    policy_key: ed25519_dalek::SigningKey,
    ws_hub: WsHub,
    connected: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut backoff = Duration::from_secs(1);

    loop {
        match listen_loop(
            database_url,
            pool.clone(),
            policy_key.clone(),
            ws_hub.clone(),
            connected.clone(),
        )
        .await
        {
            Ok(()) => {
                tracing::warn!("postgres listener exited unexpectedly, reconnecting");
            }
            Err(e) => {
                connected.store(false, Ordering::Relaxed);
                tracing::warn!(?e, "postgres listener error, reconnecting in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn listen_loop(
    database_url: &str,
    pool: PgPool,
    policy_key: ed25519_dalek::SigningKey,
    ws_hub: WsHub,
    connected: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut listener = PgListener::connect(database_url).await?;
    listener.listen(CHANNEL).await?;
    connected.store(true, Ordering::Relaxed);
    tracing::info!(channel = CHANNEL, "postgres LISTEN connected");

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();
        match Uuid::parse_str(payload) {
            Ok(network_id) => {
                ws_hub
                    .notify_network_changed(network_id, &pool, &policy_key)
                    .await;
            }
            Err(e) => {
                tracing::warn!(?e, payload, "invalid network_id in NOTIFY payload");
            }
        }
    }
}
