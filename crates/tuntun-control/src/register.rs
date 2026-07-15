use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use std::collections::HashMap;
use tuntun_common::EnrollResponse;
use uuid::Uuid;

pub struct RegisterDeviceParams {
    pub endpoint_id: String,
    pub organization_id: String,
    pub network_id: Uuid,
    pub hostname: String,
    pub os: String,
    pub agent_version: String,
    pub device_type: String,
    pub metadata: Option<serde_json::Value>,
    pub labels: Option<HashMap<String, String>>,
    pub expires_in: Option<String>,
    pub public_ip: Option<std::net::IpAddr>,
    /// `"active"` (token/SDK) or `"pending"` (quick enroll).
    pub membership_status: String,
}

pub async fn register_device(
    pool: &PgPool,
    policy_key: &SigningKey,
    params: RegisterDeviceParams,
) -> Result<EnrollResponse, (axum::http::StatusCode, String)> {
    tuntun_common::validate_endpoint_id(&params.endpoint_id).map_err(|_| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            "invalid endpoint_id".into(),
        )
    })?;
    if params.hostname.len() > 253 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "hostname too long".into(),
        ));
    }
    if params.membership_status != "active" && params.membership_status != "pending" {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "invalid membership status".into(),
        ));
    }

    let mut tx = pool.begin().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    let network_row: Option<(String,)> = sqlx::query_as(
        "SELECT organization_id FROM networks WHERE id = $1 AND organization_id = $2",
    )
    .bind(params.network_id)
    .bind(&params.organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    if network_row.is_none() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "network not found".into(),
        ));
    }

    let existing_org: Option<String> =
        sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1")
            .bind(&params.endpoint_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db: {e}"),
                )
            })?;

    if let Some(ref org) = existing_org
        && org != &params.organization_id
    {
        return Err((
            axum::http::StatusCode::CONFLICT,
            "endpoint already enrolled in another organization".into(),
        ));
    }

    let tenant_ipv6 =
        tuntun_common::ipv6::derive_tenant_ipv6(&params.endpoint_id).map_err(|_| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "invalid endpoint_id".into(),
            )
        })?;

    let alloc = crate::ip_alloc::allocate(&mut tx, params.network_id, &params.endpoint_id)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("ip alloc: {e}"),
            )
        })?;

    let initial_metadata = crate::device_metadata::initial_enroll_metadata(
        &params.hostname,
        &params.os,
        &params.agent_version,
        params.metadata.clone(),
    );

    let labels_json =
        crate::device_labels::labels_to_json(&params.labels.clone().unwrap_or_default());

    sqlx::query(
        "INSERT INTO devices (endpoint_id, organization_id, tenant_ipv6, type, name, metadata, labels, inactivity_ttl, expired_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::interval, NULL) \
         ON CONFLICT (endpoint_id) DO UPDATE \
         SET metadata = devices.metadata || EXCLUDED.metadata, \
             type = EXCLUDED.type, \
             name = EXCLUDED.name, \
             labels = CASE \
               WHEN EXCLUDED.labels = '{}'::jsonb THEN devices.labels \
               ELSE EXCLUDED.labels \
             END, \
             inactivity_ttl = CASE \
               WHEN $8::interval IS NOT NULL THEN $8::interval \
               ELSE devices.inactivity_ttl \
             END, \
             expired_at = CASE \
               WHEN $8::interval IS NOT NULL THEN NULL \
               ELSE devices.expired_at \
             END, \
             last_seen = now()",
    )
    .bind(&params.endpoint_id)
    .bind(&params.organization_id)
    .bind(crate::pg_inet::pg_ipv6_host(tenant_ipv6))
    .bind(&params.device_type)
    .bind(&params.hostname)
    .bind(initial_metadata)
    .bind(labels_json)
    .bind(params.expires_in.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    // Active always wins (token enroll can approve a pending machine).
    // Pending never downgrades an already-active membership.
    sqlx::query(
        "INSERT INTO network_memberships (endpoint_id, network_id, assigned_ip, status) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (endpoint_id, network_id) DO UPDATE \
         SET assigned_ip = EXCLUDED.assigned_ip, \
             last_seen = now(), \
             status = CASE \
               WHEN EXCLUDED.status = 'active' THEN 'active' \
               ELSE network_memberships.status \
             END",
    )
    .bind(&params.endpoint_id)
    .bind(params.network_id)
    .bind(crate::pg_inet::pg_host(alloc.ip))
    .bind(&params.membership_status)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    let (final_status,): (String,) = sqlx::query_as(
        "SELECT status FROM network_memberships WHERE endpoint_id = $1 AND network_id = $2",
    )
    .bind(&params.endpoint_id)
    .bind(params.network_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    sqlx::query("UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1")
        .bind(&params.organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

    sqlx::query("SELECT pg_notify('tuntun:org_changed', $1)")
        .bind(&params.organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

    sqlx::query("UPDATE networks SET version = version + 1 WHERE id = $1")
        .bind(params.network_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

    sqlx::query("SELECT pg_notify('tuntun:network_changed', $1)")
        .bind(params.network_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

    let (network_name,): (String,) = sqlx::query_as("SELECT name FROM networks WHERE id = $1")
        .bind(params.network_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

    tx.commit().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db: {e}"),
        )
    })?;

    if let Some(ip) = params.public_ip {
        let _ = crate::presence::set_public_ip(pool, &params.endpoint_id, ip).await;
    }

    let metadata = params.metadata.clone().unwrap_or_else(|| {
        serde_json::json!({
            "hostname": params.hostname,
            "os": params.os,
            "agentVersion": params.agent_version,
            "kind": params.device_type,
            "reportedAt": chrono::Utc::now().to_rfc3339(),
        })
    });

    let snap = if final_status == "active" {
        crate::snapshot::build_endpoint_snapshot(pool, policy_key, &params.endpoint_id)
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("snapshot: {e}"),
                )
            })?
    } else {
        empty_pending_snapshot()
    };

    let audit_action = if final_status == "pending" {
        "device.enroll_pending"
    } else {
        "device.enrolled"
    };

    crate::audit::log(
        pool,
        Some(&params.organization_id),
        Some(&params.endpoint_id),
        audit_action,
        Some(&params.endpoint_id),
        serde_json::json!({
            "hostname": params.hostname,
            "ip": alloc.ip,
            "type": params.device_type,
            "status": final_status,
        }),
        None,
    )
    .await;

    let pool_bg = pool.clone();
    let endpoint_id = params.endpoint_id.clone();
    let hostname = params.hostname.clone();
    let agent_version = params.agent_version.clone();
    let os = params.os.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::device_metadata::merge_device_metadata(
            &pool_bg,
            &endpoint_id,
            &hostname,
            &agent_version,
            &os,
            metadata,
        )
        .await
        {
            tracing::warn!(endpoint_id = %endpoint_id, error = %e, "metadata update failed");
        }
    });

    Ok(EnrollResponse {
        organization_id: params.organization_id,
        network_id: params.network_id,
        network_name,
        status: final_status,
        snapshot: snap,
    })
}

fn empty_pending_snapshot() -> tuntun_common::EndpointSnapshot {
    tuntun_common::EndpointSnapshot {
        ipv6_enabled: false,
        tenant_ipv6: None,
        memberships: vec![],
        ipv6_peers: vec![],
        org_policy: tuntun_common::policy::PolicyBundle::default(),
        org_ca_pem: None,
        labels: std::collections::HashMap::new(),
        expires_at: None,
        version: 0,
    }
}
