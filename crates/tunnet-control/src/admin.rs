use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use uuid::Uuid;

use crate::service_auth::ServiceAuthError;
use crate::state::AppState;

/// Thin admin API state: shared `AppState` plus build version for health.
#[derive(Clone)]
pub struct AdminState {
    pub app: Arc<AppState>,
    pub version: &'static str,
}

impl AdminState {
    pub fn new(app: Arc<AppState>, version: &'static str) -> Self {
        Self { app, version }
    }
}

impl Deref for AdminState {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.app
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    ws_connections: i64,
    listen_connected: bool,
}

#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
    db: bool,
    listen: bool,
}

#[derive(Serialize)]
struct ValidateNetworkResponse {
    network_id: Uuid,
    organization_id: String,
    version: i64,
    device_count: i64,
}

#[derive(serde::Deserialize)]
struct RegisterDeviceRequest {
    endpoint_id: String,
    organization_id: String,
    network_id: Uuid,
    hostname: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    agent_version: String,
    #[serde(default = "default_device_type")]
    device_type: String,
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    labels: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    expires_in: Option<String>,
}

fn default_device_type() -> String {
    "sdk".into()
}

pub async fn serve(bind: &str, state: AdminState) -> anyhow::Result<()> {
    let router = Router::new()
        .route("/internal/v1/health", get(health_handler))
        .route("/internal/v1/ready", get(ready_handler))
        .route(
            "/internal/v1/networks/{network_id}/validate",
            post(validate_network_handler),
        )
        .route(
            "/internal/v1/devices/register",
            post(register_device_handler),
        )
        .route("/internal/v1/tunnels/open", post(open_tunnel_handler))
        .route("/internal/v1/tunnels/stop", post(stop_tunnel_handler))
        .route("/internal/v1/serves/start", post(start_serve_handler))
        .route("/internal/v1/serves/stop", post(stop_serve_handler))
        .route(
            "/internal/v1/ssh/kill-session",
            post(kill_ssh_session_handler),
        )
        .route("/internal/v1/transfers/send", post(send_file_handler))
        .route(
            "/internal/v1/transfers/accept",
            post(accept_transfer_handler),
        )
        .route(
            "/internal/v1/transfers/reject",
            post(reject_transfer_handler),
        )
        .route(
            "/internal/v1/transfers/set-consent",
            post(set_send_consent_handler),
        )
        .route(
            "/internal/v1/posture/recheck",
            post(posture_recheck_handler),
        )
        .route(
            "/internal/v1/posture/attributes",
            get(posture_attributes_handler),
        )
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "admin API listening");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn health_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    if let Err(resp) = verify_service(&state, req).await {
        return resp;
    }

    Json(HealthResponse {
        status: "ok",
        version: state.version,
        ws_connections: state.ws_hub.connection_count(),
        listen_connected: state.listen_connected.load(Ordering::Relaxed),
    })
    .into_response()
}

async fn ready_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    if let Err(resp) = verify_service(&state, req).await {
        return resp;
    }

    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let listen_ok = state.listen_connected.load(Ordering::Relaxed);
    Json(ReadyResponse {
        ready: db_ok && listen_ok,
        db: db_ok,
        listen: listen_ok,
    })
    .into_response()
}

async fn validate_network_handler(
    State(state): State<Arc<AdminState>>,
    Path(network_id): Path<Uuid>,
    req: Request<axum::body::Body>,
) -> Response {
    if let Err(resp) = verify_service(&state, req).await {
        return resp;
    }

    let row: Option<(String, i64)> =
        match sqlx::query_as("SELECT organization_id, version FROM networks WHERE id = $1")
            .bind(network_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(?e, "db error in validate_network");
                return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
            }
        };

    let Some((organization_id, version)) = row else {
        return (StatusCode::NOT_FOUND, "network not found").into_response();
    };

    let device_count: (i64,) = match sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM network_memberships WHERE network_id = $1",
    )
    .bind(network_id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(?e, "db error counting devices");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    (
        StatusCode::OK,
        Json(ValidateNetworkResponse {
            network_id,
            organization_id,
            version,
            device_count: device_count.0,
        }),
    )
        .into_response()
}

async fn register_device_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }

    let parsed: RegisterDeviceRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };

    let outcome = crate::register::register_device(
        &state.pool,
        &state.policy_key,
        crate::register::RegisterDeviceParams {
            endpoint_id: parsed.endpoint_id,
            organization_id: parsed.organization_id,
            network_id: parsed.network_id,
            hostname: parsed.hostname,
            os: parsed.os,
            agent_version: parsed.agent_version,
            device_type: parsed.device_type,
            metadata: parsed.metadata,
            labels: parsed.labels,
            expires_in: parsed.expires_in,
            public_ip: None,
            membership_status: "active".into(),
        },
    )
    .await;

    match outcome {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, msg).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct OpenTunnelPush {
    endpoint_id: String,
    tunnel_id: String,
    relay_addr: String,
    subdomain: String,
    public_hostname: String,
    local_port: u16,
    protocol: String,
    auth_token: String,
    #[serde(default)]
    redirect_rules: Vec<tunnet_common::RedirectRule>,
    #[serde(default)]
    target_addr: Option<String>,
}

#[derive(serde::Deserialize)]
struct StopTunnelPush {
    endpoint_id: String,
    tunnel_id: String,
}

async fn open_tunnel_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }
    let parsed: OpenTunnelPush = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::OpenTunnel {
                tunnel_id: parsed.tunnel_id,
                relay_addr: parsed.relay_addr,
                subdomain: parsed.subdomain,
                public_hostname: parsed.public_hostname,
                local_port: parsed.local_port,
                protocol: parsed.protocol,
                auth_token: parsed.auth_token,
                redirect_rules: parsed.redirect_rules,
                target_addr: parsed.target_addr,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn stop_tunnel_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }
    let parsed: StopTunnelPush = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::StopTunnel {
                tunnel_id: parsed.tunnel_id,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
struct StartServePush {
    endpoint_id: String,
    serve_id: String,
    port: u16,
    protocol: String,
    internal_hostname: String,
    certificate_pem: Option<String>,
    private_key_pem: Option<String>,
    #[serde(default = "default_all_peers")]
    access_mode: String,
    #[serde(default)]
    allowed_tags: Vec<String>,
    #[serde(default)]
    allowed_endpoint_ids: Vec<String>,
    #[serde(default)]
    target_addr: Option<String>,
}

fn default_all_peers() -> String {
    "all_peers".into()
}

#[derive(serde::Deserialize)]
struct StopServePush {
    endpoint_id: String,
    serve_id: String,
}

async fn start_serve_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }
    let parsed: StartServePush = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::StartServe {
                serve_id: parsed.serve_id,
                port: parsed.port,
                protocol: parsed.protocol,
                internal_hostname: parsed.internal_hostname,
                certificate_pem: parsed.certificate_pem,
                private_key_pem: parsed.private_key_pem,
                access_mode: parsed.access_mode,
                allowed_tags: parsed.allowed_tags,
                allowed_endpoint_ids: parsed.allowed_endpoint_ids,
                target_addr: parsed.target_addr,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn stop_serve_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }
    let parsed: StopServePush = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::StopServe {
                serve_id: parsed.serve_id,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
struct KillSshSessionPush {
    endpoint_id: String,
    session_id: String,
}

async fn kill_ssh_session_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(resp) = state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
    {
        return resp;
    }
    let parsed: KillSshSessionPush = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::KillSshSession {
                session_id: parsed.session_id,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
struct SendFilePush {
    endpoint_id: String,
    transfer_id: String,
    path: String,
    target: String,
    #[serde(default)]
    message: Option<String>,
}

async fn send_file_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parsed, state) = match parse_admin_json::<SendFilePush>(state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::SendFile {
                transfer_id: parsed.transfer_id,
                path: parsed.path,
                target: parsed.target,
                message: parsed.message,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
struct TransferIdPush {
    endpoint_id: String,
    transfer_id: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn accept_transfer_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parsed, state) = match parse_admin_json::<TransferIdPush>(state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::AcceptTransfer {
                transfer_id: parsed.transfer_id,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn reject_transfer_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parsed, state) = match parse_admin_json::<TransferIdPush>(state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::RejectTransfer {
                transfer_id: parsed.transfer_id,
                reason: parsed.reason,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
struct SetSendConsentPush {
    endpoint_id: String,
    mode: String,
    #[serde(default)]
    inbox_path: Option<String>,
    #[serde(default)]
    pin_blobs: bool,
}

async fn set_send_consent_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parsed, state) = match parse_admin_json::<SetSendConsentPush>(state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    state
        .ws_hub
        .push_to(
            &parsed.endpoint_id,
            tunnet_common::ws::ServerMsg::SetSendConsent {
                mode: parsed.mode,
                inbox_path: parsed.inbox_path,
                pin_blobs: parsed.pin_blobs,
            },
        )
        .await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn parse_admin_json<T: serde::de::DeserializeOwned>(
    state: Arc<AdminState>,
    req: Request<axum::body::Body>,
) -> Result<(T, Arc<AdminState>), Response> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())?;
    let parsed: T = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid json").into_response())?;
    Ok((parsed, state))
}

#[derive(serde::Deserialize)]
struct PostureRecheckPush {
    endpoint_id: String,
}

async fn posture_recheck_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parsed, state) = match parse_admin_json::<PostureRecheckPush>(state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    crate::posture::request_posture_recheck(&state.ws_hub, &parsed.endpoint_id).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn posture_attributes_handler(
    State(state): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let endpoint_id = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                (k == "endpoint_id").then(|| v.to_string())
            })
        })
        .unwrap_or_default();
    if let Err(resp) = verify_service(&state, req).await {
        return resp;
    }
    if endpoint_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "endpoint_id query param required").into_response();
    }
    match crate::posture::load_device_attributes(&state.pool, &endpoint_id).await {
        Ok(attrs) => {
            let json = crate::posture::json_attributes(&attrs);
            (StatusCode::OK, Json(json)).into_response()
        }
        Err(e) => {
            tracing::warn!(?e, %endpoint_id, "posture attributes load failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn verify_service(
    state: &AdminState,
    req: Request<axum::body::Body>,
) -> Result<(), Response> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;

    state
        .service_auth
        .verify(&method, &path, &headers, &body)
        .await
        .map_err(|e: ServiceAuthError| e.into_response())
}
