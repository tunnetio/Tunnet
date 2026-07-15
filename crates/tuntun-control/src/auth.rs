//! Signature-based agent auth.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use tuntun_common::{HDR_ENDPOINT_ID, HDR_SIGNATURE, HDR_TIMESTAMP, MAX_SKEW_SECS};

use crate::state::SharedState;

pub struct AuthedRequest {
    pub endpoint_id: String,
    pub body: bytes::Bytes,
    pub organization_id: String,
}

#[derive(Debug)]
pub struct AuthError(pub StatusCode, pub &'static str);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

pub async fn authenticate(
    state: &SharedState,
    req: Request<Body>,
    method: &str,
    path: &str,
) -> Result<AuthedRequest, AuthError> {
    authenticate_with_limit(state, req, method, path, 64 * 1024).await
}

pub async fn authenticate_with_limit(
    state: &SharedState,
    req: Request<Body>,
    method: &str,
    path: &str,
    max_body: usize,
) -> Result<AuthedRequest, AuthError> {
    let (parts, body) = req.into_parts();

    let endpoint_id = parts
        .headers
        .get(HDR_ENDPOINT_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            state.metrics.auth_failure("missing_id");
            AuthError(StatusCode::UNAUTHORIZED, "missing X-Endpoint-Id")
        })?
        .to_string();

    if tuntun_common::validate_endpoint_id(&endpoint_id).is_err() {
        state.metrics.auth_failure("bad_id");
        return Err(AuthError(StatusCode::BAD_REQUEST, "invalid X-Endpoint-Id"));
    }

    let ts: i64 = parts
        .headers
        .get(HDR_TIMESTAMP)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            state.metrics.auth_failure("bad_ts");
            AuthError(StatusCode::UNAUTHORIZED, "missing X-Timestamp")
        })?;

    if (Utc::now().timestamp() - ts).abs() > MAX_SKEW_SECS {
        state.metrics.auth_failure("stale_ts");
        return Err(AuthError(StatusCode::UNAUTHORIZED, "stale timestamp"));
    }

    let sig = parts
        .headers
        .get(HDR_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            state.metrics.auth_failure("missing_sig");
            AuthError(StatusCode::UNAUTHORIZED, "missing X-Endpoint-Signature")
        })?
        .to_string();

    let body = to_bytes(body, max_body)
        .await
        .map_err(|_| AuthError(StatusCode::PAYLOAD_TOO_LARGE, "body too large"))?;

    let organization_id: Option<String> =
        sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1")
            .bind(&endpoint_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(?e, "db error in auth");
                AuthError(StatusCode::INTERNAL_SERVER_ERROR, "db error")
            })?;

    let organization_id = organization_id.ok_or_else(|| {
        state.metrics.auth_failure("unknown_device");
        AuthError(StatusCode::UNAUTHORIZED, "unknown device; enroll first")
    })?;

    let active_membership: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_memberships WHERE endpoint_id = $1 AND status = 'active'",
    )
    .bind(&endpoint_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(?e, "db error in auth");
        AuthError(StatusCode::INTERNAL_SERVER_ERROR, "db error")
    })?;

    if active_membership.unwrap_or(0) == 0 {
        state.metrics.auth_failure("unknown_device");
        return Err(AuthError(
            StatusCode::UNAUTHORIZED,
            "unknown device; enroll first",
        ));
    }

    if crate::device_expiry::is_device_expired(&state.pool, &endpoint_id)
        .await
        .unwrap_or(true)
    {
        state.metrics.auth_failure("expired_device");
        return Err(AuthError(
            StatusCode::FORBIDDEN,
            "device expired; re-enroll required",
        ));
    }

    let vk = tuntun_common::signing::verifying_key_from_hex(&endpoint_id)
        .map_err(|_| AuthError(StatusCode::BAD_REQUEST, "invalid pubkey"))?;

    tuntun_common::signing::verify(&vk, method, path, ts, &body, &sig).map_err(|_| {
        state.metrics.auth_failure("bad_sig");
        AuthError(StatusCode::UNAUTHORIZED, "bad signature")
    })?;

    Ok(AuthedRequest {
        endpoint_id,
        body,
        organization_id,
    })
}
