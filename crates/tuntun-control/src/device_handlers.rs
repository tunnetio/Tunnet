use std::collections::HashMap;

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{AuthError, authenticate};
use crate::device_labels::{labels_to_json, merge_labels, normalize_labels};
use crate::pg_notify;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct PatchDeviceLabelsBody {
    #[serde(flatten)]
    pub labels: HashMap<String, Option<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PatchDeviceExpiryBody {
    pub expires_in: Option<String>,
}

pub async fn get_device_labels_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return (c, m).into_response(),
    };

    let row: Option<(Value,)> = sqlx::query_as("SELECT labels FROM devices WHERE endpoint_id = $1")
        .bind(&auth.endpoint_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let Some((labels,)) = row else {
        return (StatusCode::NOT_FOUND, "device not found").into_response();
    };

    (StatusCode::OK, Json(normalize_labels(&labels))).into_response()
}

pub async fn patch_device_labels_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return (c, m).into_response(),
    };

    let patch: PatchDeviceLabelsBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };

    if patch.labels.is_empty() {
        return (StatusCode::BAD_REQUEST, "at least one label required").into_response();
    }

    match merge_device_labels(
        &state,
        &auth.endpoint_id,
        &auth.organization_id,
        &patch.labels,
    )
    .await
    {
        Ok(labels) => (StatusCode::OK, Json(labels)).into_response(),
        Err((code, msg)) => (code, msg).into_response(),
    }
}

pub async fn patch_device_expiry_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return (c, m).into_response(),
    };

    let patch: PatchDeviceExpiryBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };

    let pg_interval = match resolve_expires_in_input(patch.expires_in.as_deref()) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    let result = sqlx::query(
        "UPDATE devices \
         SET inactivity_ttl = $1::interval, \
             expired_at = NULL \
         WHERE endpoint_id = $2 AND organization_id = $3",
    )
    .bind(pg_interval)
    .bind(&auth.endpoint_id)
    .bind(&auth.organization_id)
    .execute(&state.pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            (StatusCode::NOT_FOUND, "device not found").into_response()
        }
        Ok(_) => {
            let _ = sqlx::query(
                "UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1",
            )
            .bind(&auth.organization_id)
            .execute(&state.pool)
            .await;
            let _ = pg_notify::emit_org_changed(&state.pool, &auth.organization_id).await;
            (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")).into_response(),
    }
}

pub async fn merge_device_labels(
    state: &SharedState,
    endpoint_id: &str,
    organization_id: &str,
    patch: &HashMap<String, Option<String>>,
) -> Result<HashMap<String, String>, (StatusCode, String)> {
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT labels FROM devices WHERE endpoint_id = $1 AND organization_id = $2",
    )
    .bind(endpoint_id)
    .bind(organization_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let Some((existing,)) = row else {
        return Err((StatusCode::NOT_FOUND, "device not found".into()));
    };

    let merged = merge_labels(&normalize_labels(&existing), patch);
    let labels_json = labels_to_json(&merged);

    sqlx::query("UPDATE devices SET labels = $1 WHERE endpoint_id = $2")
        .bind(labels_json)
        .bind(endpoint_id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    sqlx::query("UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1")
        .bind(organization_id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    pg_notify::emit_org_changed(&state.pool, organization_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("notify: {e}")))?;

    crate::audit::log(
        &state.pool,
        Some(organization_id),
        Some(endpoint_id),
        "device.labels_updated",
        Some(endpoint_id),
        serde_json::json!({ "labels": merged }),
        None,
    )
    .await;

    Ok(merged)
}

pub fn resolve_expires_in_input(raw: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if raw.eq_ignore_ascii_case("never") {
        return Ok(None);
    }
    let secs = tuntun_common::duration::parse_human_duration_secs(raw)
        .ok_or("invalid expires_in duration")?;
    Ok(Some(tuntun_common::duration::seconds_to_pg_interval(secs)))
}

pub async fn resolve_enroll_expires_in(
    pool: &sqlx::PgPool,
    organization_id: &str,
    requested: Option<&str>,
) -> Result<Option<String>, (StatusCode, String)> {
    if let Some(raw) = requested {
        return resolve_expires_in_input(Some(raw))
            .map_err(|msg| (StatusCode::BAD_REQUEST, msg.into()));
    }

    let org_default: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT \
           settings->'machines'->'autoCleanup'->>'inactivityAfter', \
           COALESCE((settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
         FROM organization WHERE id = $1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let Some((inactivity_after, enabled)) = org_default else {
        return Ok(None);
    };
    if !enabled.unwrap_or(false) {
        return Ok(None);
    }
    let Some(raw) = inactivity_after else {
        return Ok(None);
    };
    resolve_expires_in_input(Some(&raw)).map_err(|msg| (StatusCode::BAD_REQUEST, msg.into()))
}
