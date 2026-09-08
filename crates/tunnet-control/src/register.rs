use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use std::collections::HashMap;
use tunnet_audit::AuditEmitter;
use tunnet_common::EnrollResponse;
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
    pub expires_in: Option<i64>,
    pub public_ip: Option<std::net::IpAddr>,
    /// `"active"` (token/SDK) or `"pending"` (quick enroll).
    pub membership_status: String,
    pub enrollment_token_hash: Option<String>,
}

pub async fn register_device(
    pool: &PgPool,
    policy_key: &SigningKey,
    audit: &AuditEmitter,
    params: RegisterDeviceParams,
) -> Result<EnrollResponse, (axum::http::StatusCode, String)> {
    tunnet_common::validate_endpoint_id(&params.endpoint_id).map_err(|_| {
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

    if let Some(token_hash) = params.enrollment_token_hash.as_deref() {
        let consumed = sqlx::query(
            "UPDATE enrollment_tokens SET used_at = now() \
             WHERE token_hash = $1 AND network_id = $2 \
               AND used_at IS NULL AND expires_at > now()",
        )
        .bind(token_hash)
        .bind(params.network_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

        if consumed.rows_affected() != 1 {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid or expired enrollment token".into(),
            ));
        }
    }

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

    if existing_org.is_none()
        && crate::relay_map::license_tier() == tunnet_license::LicenseTier::Cloud
    {
        let plan_row: Option<(String, Option<i32>)> = sqlx::query_as(
            "SELECT plan, seats FROM subscription \
             WHERE reference_id = $1 AND status IN ('active', 'trialing') \
             ORDER BY period_end DESC NULLS LAST \
             LIMIT 1",
        )
        .bind(&params.organization_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db: {e}"),
            )
        })?;

        let resource_limit: i64 = match plan_row.as_ref() {
            Some((plan, seats)) => match plan.as_str() {
                "personal" => 100,
                "team" => {
                    let seat_count = seats.unwrap_or(2).max(2) as i64;
                    100 + 25 * (seat_count - 2).max(0)
                }
                "business" => {
                    let seat_count = seats.unwrap_or(5).max(5) as i64;
                    500 + 50 * (seat_count - 5).max(0)
                }
                "enterprise" => i64::MAX,
                _ => 20, // free / unknown
            },
            None => 20,
        };

        if resource_limit < i64::MAX {
            let device_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM devices WHERE organization_id = $1",
            )
            .bind(&params.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db: {e}"),
                )
            })?;

            if device_count >= resource_limit {
                return Err((
                    axum::http::StatusCode::PAYMENT_REQUIRED,
                    format!(
                        "Organization resource limit reached ({resource_limit}). Upgrade the plan to enroll more machines."
                    ),
                ));
            }
        }
    }

    let tenant_ipv6 =
        tunnet_common::ipv6::derive_tenant_ipv6(&params.endpoint_id).map_err(|_| {
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
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::bigint * interval '1 second', NULL) \
         ON CONFLICT (endpoint_id) DO UPDATE \
         SET metadata = devices.metadata || EXCLUDED.metadata, \
             type = EXCLUDED.type, \
             name = EXCLUDED.name, \
             labels = CASE \
               WHEN EXCLUDED.labels = '{}'::jsonb THEN devices.labels \
               ELSE EXCLUDED.labels \
             END, \
             inactivity_ttl = CASE \
               WHEN $8::bigint IS NOT NULL THEN $8::bigint * interval '1 second' \
               ELSE devices.inactivity_ttl \
             END, \
             expired_at = CASE \
               WHEN $8::bigint IS NOT NULL THEN NULL \
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
    .bind(params.expires_in)
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

    sqlx::query("SELECT pg_notify('tunnet:org_changed', $1)")
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

    sqlx::query("SELECT pg_notify('tunnet:network_changed', $1)")
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
            "reportedAt": jiff::Timestamp::now().to_string(),
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
        audit,
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
    );

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
        management_url: std::env::var("MANAGEMENT_URL")
            .ok()
            .filter(|s| !s.is_empty()),
        dashboard_url: std::env::var("DASHBOARD_URL")
            .ok()
            .filter(|s| !s.is_empty()),
    })
}

fn empty_pending_snapshot() -> tunnet_common::EndpointSnapshot {
    tunnet_common::EndpointSnapshot {
        ipv6_enabled: false,
        tenant_ipv6: None,
        memberships: vec![],
        network_revisions: std::collections::HashMap::new(),
        ipv6_peers: vec![],
        org_policy: tunnet_common::policy::PolicyBundle::default(),
        policy_verifying_key: None,
        agent_policy: tunnet_common::RemoteAgentPolicy::default(),
        connectivity_relays: vec![],
        connectivity_relay_fallback: tunnet_common::ConnectivityRelayFallback::None,
        org_ca_pem: None,
        labels: Default::default(),
        expires_at: None,
        version: 0,
    }
}
