//! Agent-facing SSH check-mode auth evaluate / poll / verify.

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AuthError, authenticate};
use crate::state::SharedState;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

type ChallengePollRow = (
    String,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
    chrono::DateTime<chrono::Utc>,
    String,
);

type ProofVerifyRow = (
    String,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

fn management_base(_state: &SharedState) -> String {
    std::env::var("DASHBOARD_URL")
        .unwrap_or_else(|_| "http://localhost:5173".into())
        .trim_end_matches('/')
        .to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateSshAuthBody {
    pub peer_endpoint_id: String,
    pub check_period_secs: u64,
}

/// Destination agent: is this peer's last IdP auth still fresh?
/// If not, mint a challenge and return a browser reauth URL.
pub async fn evaluate_ssh_auth_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: EvaluateSshAuthBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if body.check_period_secs == 0 {
        return err(StatusCode::BAD_REQUEST, "checkPeriodSecs must be > 0");
    }
    if tuntun_common::validate_endpoint_id(&body.peer_endpoint_id).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid peerEndpointId");
    }

    // Caller (dst) and peer must share an active network.
    let membership: Option<(Uuid, String)> = match sqlx::query_as(
        "SELECT nm.network_id, d.organization_id \
         FROM network_memberships nm \
         JOIN devices d ON d.endpoint_id = nm.endpoint_id \
         JOIN network_memberships peer ON peer.network_id = nm.network_id \
           AND peer.endpoint_id = $2 AND peer.status = 'active' \
         WHERE nm.endpoint_id = $1 AND nm.status = 'active' \
         LIMIT 1",
    )
    .bind(&auth.endpoint_id)
    .bind(&body.peer_endpoint_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let Some((network_id, org_id)) = membership else {
        return err(StatusCode::FORBIDDEN, "no shared active network");
    };

    let last_auth: Option<(chrono::DateTime<chrono::Utc>,)> =
        match sqlx::query_as("SELECT authenticated_at FROM ssh_auth_checks WHERE endpoint_id = $1")
            .bind(&body.peer_endpoint_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };

    if let Some((authenticated_at,)) = last_auth {
        let age = chrono::Utc::now() - authenticated_at;
        if age.num_seconds() >= 0 && (age.num_seconds() as u64) < body.check_period_secs {
            return (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "authenticatedAt": authenticated_at.to_rfc3339(),
                })),
            )
                .into_response();
        }
    }

    let challenge = random_token();
    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
    if let Err(e) = sqlx::query(
        "INSERT INTO ssh_auth_challenges \
           (token, organization_id, network_id, endpoint_id, dst_endpoint_id, status, expires_at) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6)",
    )
    .bind(&challenge)
    .bind(&org_id)
    .bind(network_id)
    .bind(&body.peer_endpoint_id)
    .bind(&auth.endpoint_id)
    .bind(expires)
    .execute(&state.pool)
    .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    let reauth_url = format!("{}/auth/ssh?token={challenge}", management_base(&state));
    (
        StatusCode::OK,
        Json(json!({
            "status": "reauth_required",
            "reauthUrl": reauth_url,
            "challengeToken": challenge,
            "expiresAt": expires.to_rfc3339(),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollSshAuthBody {
    pub challenge_token: String,
}

/// Source agent / CLI: wait for browser re-auth to complete and fetch proof.
pub async fn poll_ssh_auth_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: PollSshAuthBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };

    let row: Option<ChallengePollRow> = match sqlx::query_as(
        "SELECT status, proof_token, proof_expires_at, expires_at, endpoint_id \
             FROM ssh_auth_challenges WHERE token = $1",
    )
    .bind(&body.challenge_token)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let Some((status, proof_token, proof_expires_at, expires_at, endpoint_id)) = row else {
        return err(StatusCode::NOT_FOUND, "challenge not found");
    };

    // Only the peer being authenticated (source) may poll.
    if !endpoint_id.eq_ignore_ascii_case(&auth.endpoint_id) {
        return err(
            StatusCode::FORBIDDEN,
            "challenge belongs to another endpoint",
        );
    }

    if status == "pending" && chrono::Utc::now() > expires_at {
        let _ = sqlx::query(
            "UPDATE ssh_auth_challenges SET status = 'expired' WHERE token = $1 AND status = 'pending'",
        )
        .bind(&body.challenge_token)
        .execute(&state.pool)
        .await;
        return (StatusCode::OK, Json(json!({ "status": "expired" }))).into_response();
    }

    match status.as_str() {
        "pending" => (StatusCode::OK, Json(json!({ "status": "pending" }))).into_response(),
        "completed" => {
            let Some(proof) = proof_token else {
                return (
                    StatusCode::OK,
                    Json(json!({ "status": "failed", "error": "missing proof" })),
                )
                    .into_response();
            };
            if let Some(exp) = proof_expires_at
                && chrono::Utc::now() > exp
            {
                return (StatusCode::OK, Json(json!({ "status": "expired" }))).into_response();
            }
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ready",
                    "proofToken": proof,
                })),
            )
                .into_response()
        }
        "expired" => (StatusCode::OK, Json(json!({ "status": "expired" }))).into_response(),
        _ => (
            StatusCode::OK,
            Json(json!({ "status": "failed", "error": status })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySshAuthBody {
    pub peer_endpoint_id: String,
    pub check_period_secs: u64,
    #[serde(default)]
    pub auth_token: Option<String>,
}

/// Destination agent: accept a one-time proof token and/or last-auth within period.
pub async fn verify_ssh_auth_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: VerifySshAuthBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if tuntun_common::validate_endpoint_id(&body.peer_endpoint_id).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid peerEndpointId");
    }

    let shared: Option<(i32,)> = match sqlx::query_as(
        "SELECT 1 FROM network_memberships a \
         JOIN network_memberships b ON b.network_id = a.network_id \
           AND b.endpoint_id = $2 AND b.status = 'active' \
         WHERE a.endpoint_id = $1 AND a.status = 'active' LIMIT 1",
    )
    .bind(&auth.endpoint_id)
    .bind(&body.peer_endpoint_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    if shared.is_none() {
        return err(StatusCode::FORBIDDEN, "no shared active network");
    }

    if let Some(token) = body.auth_token.as_deref().filter(|t| !t.is_empty()) {
        let row: Option<ProofVerifyRow> = match sqlx::query_as(
            "SELECT status, endpoint_id, proof_expires_at, proof_consumed_at \
             FROM ssh_auth_challenges WHERE proof_token = $1",
        )
        .bind(token)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };
        if let Some((status, endpoint_id, proof_expires_at, proof_consumed_at)) = row
            && status == "completed"
            && endpoint_id.eq_ignore_ascii_case(&body.peer_endpoint_id)
            && proof_consumed_at.is_none()
            && proof_expires_at
                .map(|exp| chrono::Utc::now() <= exp)
                .unwrap_or(true)
        {
            let _ = sqlx::query(
                "UPDATE ssh_auth_challenges SET proof_consumed_at = now() \
                 WHERE proof_token = $1 AND proof_consumed_at IS NULL",
            )
            .bind(token)
            .execute(&state.pool)
            .await;
            return (
                StatusCode::OK,
                Json(json!({ "status": "ok", "method": "proof" })),
            )
                .into_response();
        }
        // Fall through to last-auth check if proof invalid.
    }

    let last_auth: Option<(chrono::DateTime<chrono::Utc>,)> =
        match sqlx::query_as("SELECT authenticated_at FROM ssh_auth_checks WHERE endpoint_id = $1")
            .bind(&body.peer_endpoint_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };

    if let Some((authenticated_at,)) = last_auth {
        let age = chrono::Utc::now() - authenticated_at;
        if age.num_seconds() >= 0 && (age.num_seconds() as u64) < body.check_period_secs {
            return (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "method": "last_auth",
                    "authenticatedAt": authenticated_at.to_rfc3339(),
                })),
            )
                .into_response();
        }
    }

    (StatusCode::OK, Json(json!({ "status": "reauth_required" }))).into_response()
}
