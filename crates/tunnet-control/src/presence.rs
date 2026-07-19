//! Device agent presence: WebSocket connect/disconnect and heartbeats.

use std::net::IpAddr;

use sqlx::PgPool;
use tunnet_common::PeerEntry;
use uuid::Uuid;

use crate::pg_inet;
use crate::ws_hub::WsHub;

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

async fn bump_network_version(pool: &PgPool, network_id: Uuid) -> anyhow::Result<u64> {
    let version: i64 = sqlx::query_scalar(
        "UPDATE networks SET version = version + 1 WHERE id = $1 RETURNING version",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    Ok(version as u64)
}

/// Load a single active peer entry for delta broadcasts.
pub async fn load_peer_entry(
    pool: &PgPool,
    network_id: Uuid,
    endpoint_id: &str,
) -> anyhow::Result<Option<PeerEntry>> {
    let row: Option<(String, String, pg_inet::PgIp, Option<String>)> = sqlx::query_as(
        "SELECT e.endpoint_id, \
            COALESCE(NULLIF(e.metadata->>'hostname', ''), left(e.endpoint_id, 8)) AS hostname, \
            nm.assigned_ip::inet, \
            NULLIF(e.metadata->>'sshHostKey', '') AS ssh_host_key \
         FROM network_memberships nm \
         JOIN devices e ON e.endpoint_id = nm.endpoint_id \
         WHERE nm.network_id = $1 AND nm.status = 'active' AND nm.endpoint_id = $2 \
           AND e.expired_at IS NULL",
    )
    .bind(network_id)
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await?;

    let Some((eid, host, assigned_ip, ssh_host_key)) = row else {
        return Ok(None);
    };
    let ip = match pg_inet::to_ipv4_addr(assigned_ip) {
        Ok(ip) => ip,
        Err(_) => return Ok(None),
    };
    let tag_rows: Vec<(String,)> =
        sqlx::query_as("SELECT tag FROM device_tags WHERE endpoint_id = $1")
            .bind(&eid)
            .fetch_all(pool)
            .await?;
    Ok(Some(PeerEntry {
        ip,
        endpoint_id: eid,
        hostname: host,
        tags: tag_rows.into_iter().map(|(t,)| t).collect(),
        ssh_host_key,
    }))
}

/// Push a peer-joined delta to other WS agents (avoids full snapshot storm).
pub async fn notify_peer_joined(
    pool: &PgPool,
    ws_hub: &WsHub,
    network_id: Uuid,
    endpoint_id: &str,
) -> anyhow::Result<()> {
    let Some(peer) = load_peer_entry(pool, network_id, endpoint_id).await? else {
        return Ok(());
    };
    let version = bump_network_version(pool, network_id).await?;
    ws_hub
        .notify_peer_joined(network_id, endpoint_id, peer, version)
        .await;
    Ok(())
}

/// Push a peer-left delta when membership is actually removed (not mere presence).
#[allow(dead_code)] // public helper for membership revocation paths
pub async fn notify_peer_left(
    pool: &PgPool,
    ws_hub: &WsHub,
    network_id: Uuid,
    endpoint_id: &str,
) -> anyhow::Result<()> {
    let version = bump_network_version(pool, network_id).await?;
    ws_hub
        .notify_peer_left(network_id, endpoint_id, version)
        .await;
    Ok(())
}

pub async fn mark_agent_connected(
    pool: &PgPool,
    endpoint_id: &str,
    public_ip: Option<IpAddr>,
    ws_hub: Option<&WsHub>,
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
    // Peer membership is unchanged by presence; push a cheap Delta so peers refresh
    // metadata (hostname / ssh keys) without a full Snapshot storm.
    if let Some(hub) = ws_hub
        && let Err(e) = notify_peer_joined(pool, hub, device.network_id, endpoint_id).await
    {
        tracing::warn!(?e, %endpoint_id, "peer-joined delta on connect failed");
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
    // Do not remove peers or storm Snapshots: mesh routes include offline members.
    // Use `notify_peer_left` only when membership is actually revoked.
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
