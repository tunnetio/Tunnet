//! Machine inactivity auto-cleanup: soft-expire, hard-delete, or soft then hard.
//!
//! Deadline is derived as `last_seen + effective_ttl` (device override or org policy).
//! There is no stored `expires_at` column.

use sqlx::PgPool;
use uuid::Uuid;

use crate::pg_notify;
use crate::ws_hub::WsHub;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupMode {
    Hard,
    Soft,
    SoftThenHard,
}

impl CleanupMode {
    fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("hard") => Self::Hard,
            Some("soft_then_hard") => Self::SoftThenHard,
            _ => Self::Soft,
        }
    }
}

/// Run one cleanup pass.
pub async fn run_cleanup(pool: &PgPool, ws_hub: &WsHub) -> anyhow::Result<(u64, u64)> {
    let soft = soft_expire_due_devices(pool, ws_hub).await?;
    let hard = hard_delete_due_devices(pool, ws_hub).await?;
    if soft > 0 || hard > 0 {
        tracing::info!(soft, hard, "machine auto-cleanup pass complete");
    }
    Ok((soft, hard))
}

async fn soft_expire_due_devices(pool: &PgPool, ws_hub: &WsHub) -> anyhow::Result<u64> {
    let due: Vec<(String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT d.endpoint_id, d.organization_id, \
                o.settings->'machines'->'autoCleanup'->>'mode', \
                COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
         FROM devices d \
         INNER JOIN organization o ON o.id = d.organization_id \
         WHERE d.expired_at IS NULL \
           AND COALESCE( \
             d.inactivity_ttl, \
             CASE \
               WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
               THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
               ELSE NULL \
             END \
           ) IS NOT NULL \
           AND d.last_seen + COALESCE( \
             d.inactivity_ttl, \
             CASE \
               WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
               THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
               ELSE NULL \
             END \
           ) < now()",
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0u64;
    for (endpoint_id, organization_id, mode_raw, org_enabled) in due {
        let mode = CleanupMode::parse(mode_raw.as_deref());
        if org_enabled && mode == CleanupMode::Hard {
            continue;
        }
        if soft_expire_device(pool, ws_hub, &endpoint_id, &organization_id).await? {
            count += 1;
        }
    }
    Ok(count)
}

async fn hard_delete_due_devices(pool: &PgPool, ws_hub: &WsHub) -> anyhow::Result<u64> {
    let hard_due: Vec<(String, String)> = sqlx::query_as(
        "SELECT d.endpoint_id, d.organization_id \
         FROM devices d \
         INNER JOIN organization o ON o.id = d.organization_id \
         WHERE COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) = true \
           AND COALESCE(o.settings->'machines'->'autoCleanup'->>'mode', 'soft') = 'hard' \
           AND COALESCE( \
             d.inactivity_ttl, \
             (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
           ) IS NOT NULL \
           AND d.last_seen + COALESCE( \
             d.inactivity_ttl, \
             (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
           ) < now()",
    )
    .fetch_all(pool)
    .await?;

    let grace_candidates: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT d.endpoint_id, d.organization_id, \
                o.settings->'machines'->'autoCleanup'->>'hardDeleteAfter' \
         FROM devices d \
         INNER JOIN organization o ON o.id = d.organization_id \
         WHERE COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) = true \
           AND COALESCE(o.settings->'machines'->'autoCleanup'->>'mode', 'soft') = 'soft_then_hard' \
           AND d.expired_at IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0u64;
    for (endpoint_id, organization_id) in hard_due {
        if hard_delete_device(pool, ws_hub, &endpoint_id, &organization_id).await? {
            count += 1;
        }
    }

    for (endpoint_id, organization_id, grace_raw) in grace_candidates {
        let Some(grace_raw) = grace_raw.as_deref() else {
            continue;
        };
        let Some(secs) = tunnet_common::duration::parse_human_duration_secs(grace_raw) else {
            continue;
        };
        let due: Option<(bool,)> = sqlx::query_as(
            "SELECT expired_at + ($2::bigint * interval '1 second') < now() \
             FROM devices WHERE endpoint_id = $1 AND expired_at IS NOT NULL",
        )
        .bind(&endpoint_id)
        .bind(secs)
        .fetch_optional(pool)
        .await?;

        if due.map(|(v,)| v).unwrap_or(false)
            && hard_delete_device(pool, ws_hub, &endpoint_id, &organization_id).await?
        {
            count += 1;
        }
    }
    Ok(count)
}

async fn soft_expire_device(
    pool: &PgPool,
    ws_hub: &WsHub,
    endpoint_id: &str,
    organization_id: &str,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;

    let updated = sqlx::query(
        "UPDATE devices \
         SET expired_at = now(), \
             agent_connected = false, \
             disconnected_at = now() \
         WHERE endpoint_id = $1 AND expired_at IS NULL",
    )
    .bind(endpoint_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if updated == 0 {
        return Ok(false);
    }

    let memberships: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE network_memberships SET status = 'expired' \
         WHERE endpoint_id = $1 AND status <> 'expired' \
         RETURNING network_id",
    )
    .bind(endpoint_id)
    .fetch_all(&mut *tx)
    .await?;

    for (network_id,) in &memberships {
        sqlx::query("UPDATE networks SET version = version + 1 WHERE id = $1")
            .bind(network_id)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query("UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1")
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    crate::audit::log(
        pool,
        Some(organization_id),
        None,
        "device.expired",
        Some(endpoint_id),
        serde_json::json!({ "reason": "inactivity_ttl", "mode": "soft" }),
        None,
    )
    .await;

    ws_hub
        .disconnect(
            endpoint_id,
            "machine expired due to inactivity; re-enroll to reconnect",
        )
        .await;

    for (network_id,) in memberships {
        let version: i64 = sqlx::query_scalar("SELECT version FROM networks WHERE id = $1")
            .bind(network_id)
            .fetch_one(pool)
            .await?;
        ws_hub
            .notify_peer_left(network_id, endpoint_id, version as u64)
            .await;
    }
    pg_notify::emit_org_changed(pool, organization_id).await?;

    Ok(true)
}

async fn hard_delete_device(
    pool: &PgPool,
    ws_hub: &WsHub,
    endpoint_id: &str,
    organization_id: &str,
) -> anyhow::Result<bool> {
    ws_hub
        .disconnect(
            endpoint_id,
            "machine deleted due to inactivity; re-enroll to reconnect",
        )
        .await;

    let mut tx = pool.begin().await?;

    let memberships: Vec<(Uuid,)> =
        sqlx::query_as("SELECT network_id FROM network_memberships WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_all(&mut *tx)
            .await?;

    for (network_id,) in &memberships {
        sqlx::query("DELETE FROM network_memberships WHERE endpoint_id = $1 AND network_id = $2")
            .bind(endpoint_id)
            .bind(network_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("UPDATE networks SET version = version + 1 WHERE id = $1")
            .bind(network_id)
            .execute(&mut *tx)
            .await?;
    }

    let deleted = sqlx::query("DELETE FROM devices WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if deleted == 0 {
        return Ok(false);
    }

    sqlx::query("UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1")
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    crate::audit::log(
        pool,
        Some(organization_id),
        None,
        "device.purged",
        Some(endpoint_id),
        serde_json::json!({ "reason": "inactivity_ttl", "mode": "hard" }),
        None,
    )
    .await;

    for (network_id,) in memberships {
        let version: i64 = sqlx::query_scalar("SELECT version FROM networks WHERE id = $1")
            .bind(network_id)
            .fetch_one(pool)
            .await?;
        ws_hub
            .notify_peer_left(network_id, endpoint_id, version as u64)
            .await;
    }
    pg_notify::emit_org_changed(pool, organization_id).await?;

    Ok(true)
}

/// True when soft-expired or past `last_seen + effective_ttl`.
pub async fn is_device_expired(pool: &PgPool, endpoint_id: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT \
           d.expired_at IS NOT NULL \
           OR ( \
             COALESCE( \
               d.inactivity_ttl, \
               CASE \
                 WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
                 THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
                 ELSE NULL \
               END \
             ) IS NOT NULL \
             AND d.last_seen + COALESCE( \
               d.inactivity_ttl, \
               CASE \
                 WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
                 THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
                 ELSE NULL \
               END \
             ) < now() \
           ) \
         FROM devices d \
         INNER JOIN organization o ON o.id = d.organization_id \
         WHERE d.endpoint_id = $1",
    )
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(v,)| v).unwrap_or(false))
}
