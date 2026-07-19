//! Device agent presence: WebSocket connect/disconnect and heartbeats.

use std::net::IpAddr;

use sqlx::PgPool;
use uuid::Uuid;

use crate::pg_inet;

pub const PRESENCE_CHANNEL: &str = "tunnet:device_presence";

pub const HEARTBEAT_STALE_SECS: i64 = 90;

struct DeviceRow {
    organization_id: String,
    network_id: Uuid,
}

async fn load_device(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<Option<DeviceRow>> {
    let org: Option<String> =
        sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_optional(pool)
            .await?;

    let Some(organization_id) = org else {
        return Ok(None);
    };

    let network_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT network_id FROM network_memberships \
         WHERE endpoint_id = $1 AND status = 'active' \
         ORDER BY first_seen ASC LIMIT 1",
    )
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await?;

    Ok(network_id.map(|network_id| DeviceRow {
        organization_id,
        network_id,
    }))
}

fn ip_to_pg(ip: IpAddr) -> pg_inet::PgIp {
    match ip {
        IpAddr::V4(v4) => pg_inet::pg_host(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                pg_inet::pg_host(v4)
            } else {
                pg_inet::PgIp::new(ip, 128).expect("host /128")
            }
        }
    }
}

pub async fn emit_presence_changed(
    pool: &PgPool,
    organization_id: &str,
    endpoint_id: &str,
) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "organizationId": organization_id,
        "endpointId": endpoint_id,
    })
    .to_string();

    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(PRESENCE_CHANNEL)
        .bind(payload)
        .execute(pool)
        .await?;
    Ok(())
}

async fn insert_presence_event(
    pool: &PgPool,
    endpoint_id: &str,
    organization_id: &str,
    network_id: Uuid,
    event: &str,
    public_ip: Option<pg_inet::PgIp>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO device_presence_events (endpoint_id, organization_id, network_id, event, public_ip) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(endpoint_id)
    .bind(organization_id)
    .bind(network_id)
    .bind(event)
    .bind(public_ip)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_agent_connected(
    pool: &PgPool,
    endpoint_id: &str,
    public_ip: Option<IpAddr>,
) -> anyhow::Result<()> {
    let Some(device) = load_device(pool, endpoint_id).await? else {
        return Ok(());
    };

    let pg_ip = public_ip.map(ip_to_pg);

    sqlx::query(crate::device_expiry_sql::SLIDE_ON_CONNECT)
        .bind(endpoint_id)
        .bind(pg_ip)
        .execute(pool)
        .await?;

    sqlx::query("UPDATE network_memberships SET last_seen = now() WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .execute(pool)
        .await?;

    insert_presence_event(
        pool,
        endpoint_id,
        &device.organization_id,
        device.network_id,
        "connected",
        pg_ip,
    )
    .await?;

    emit_presence_changed(pool, &device.organization_id, endpoint_id).await?;
    // Refresh peer snapshots for everyone else (metadata / ssh keys / membership).
    if let Err(e) = crate::pg_notify::emit_network_changed(pool, device.network_id).await {
        tracing::warn!(?e, %endpoint_id, "network_changed notify on connect failed");
    }
    tracing::info!(%endpoint_id, ?public_ip, "agent connected");
    Ok(())
}

pub async fn mark_agent_disconnected(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<()> {
    let Some(device) = load_device(pool, endpoint_id).await? else {
        return Ok(());
    };

    let updated = sqlx::query(
        "UPDATE devices \
         SET agent_connected = false, disconnected_at = now() \
         WHERE endpoint_id = $1 AND agent_connected",
    )
    .bind(endpoint_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Ok(());
    }

    insert_presence_event(
        pool,
        endpoint_id,
        &device.organization_id,
        device.network_id,
        "disconnected",
        None,
    )
    .await?;

    emit_presence_changed(pool, &device.organization_id, endpoint_id).await?;
    if let Err(e) = crate::pg_notify::emit_network_changed(pool, device.network_id).await {
        tracing::warn!(?e, %endpoint_id, "network_changed notify on disconnect failed");
    }
    tracing::info!(%endpoint_id, "agent disconnected");
    Ok(())
}

pub async fn record_heartbeat(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<()> {
    let result = sqlx::query(crate::device_expiry_sql::SLIDE_ON_HEARTBEAT)
        .bind(endpoint_id)
        .execute(pool)
        .await?;

    sqlx::query("UPDATE network_memberships SET last_seen = now() WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .execute(pool)
        .await?;

    // Push fresh lastHeartbeatAt to dashboard SSE so "last seen" stays current.
    if result.rows_affected() > 0
        && let Some(device) = load_device(pool, endpoint_id).await?
    {
        emit_presence_changed(pool, &device.organization_id, endpoint_id).await?;
    }
    Ok(())
}

pub async fn set_public_ip(
    pool: &PgPool,
    endpoint_id: &str,
    public_ip: IpAddr,
) -> anyhow::Result<()> {
    let pg_ip = ip_to_pg(public_ip);
    sqlx::query("UPDATE devices SET public_ip = $2 WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .bind(pg_ip)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn sweep_stale_connections(pool: &PgPool) -> anyhow::Result<()> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "UPDATE devices \
         SET agent_connected = false, disconnected_at = now() \
         WHERE agent_connected \
           AND last_heartbeat_at < now() - make_interval(secs => $1) \
         RETURNING endpoint_id, organization_id",
    )
    .bind(HEARTBEAT_STALE_SECS as f64)
    .fetch_all(pool)
    .await?;

    for (endpoint_id, organization_id) in rows {
        if let Some(device) = load_device(pool, &endpoint_id).await? {
            insert_presence_event(
                pool,
                &endpoint_id,
                &device.organization_id,
                device.network_id,
                "heartbeat_missed",
                None,
            )
            .await?;
        }
        emit_presence_changed(pool, &organization_id, &endpoint_id).await?;
        tracing::warn!(%endpoint_id, "agent marked disconnected (stale heartbeat)");
    }

    if let Err(e) = crate::ha::reconcile_failover(pool).await {
        tracing::warn!(?e, "HA failover reconcile failed");
    }

    Ok(())
}
