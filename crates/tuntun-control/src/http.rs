use std::sync::Arc;

use axum::body::Body;
use axum::extract::{
    ConnectInfo, State, WebSocketUpgrade,
    ws::{Message, WebSocket},
};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tuntun_common::{
    EndpointSnapshot, EnrollRequest, EnrollResponse, EnrollStatusRequest, EnrollStatusResponse,
    PollRequest, RegisterRequest,
    ws::{ClientMsg, ServerMsg},
};

use crate::auth::{AuthError, authenticate};
use crate::state::{AppState, SharedState};

pub async fn serve(state: SharedState) -> anyhow::Result<()> {
    let public = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/enroll", post(enroll_handler))
        .route("/v1/enroll/status", post(enroll_status_handler))
        .route("/v1/register", post(register_handler))
        .route("/v1/poll", post(poll_handler))
        .route(
            "/v1/device/labels",
            get(crate::device_handlers::get_device_labels_handler),
        )
        .route(
            "/v1/device/labels",
            patch(crate::device_handlers::patch_device_labels_handler),
        )
        .route(
            "/v1/device/expiry",
            patch(crate::device_handlers::patch_device_expiry_handler),
        )
        .route("/v1/ws", get(ws_handler))
        .route(
            "/v1/relay/register",
            post(crate::tunnels::relay_register_handler),
        )
        .route(
            "/v1/relay/heartbeat",
            post(crate::tunnels::relay_heartbeat_handler),
        )
        .route(
            "/v1/relay/traffic",
            post(crate::tunnels::relay_traffic_handler),
        )
        .route("/v1/tunnels", post(crate::tunnels::create_tunnel_handler))
        .route(
            "/v1/tunnels/ready",
            post(crate::tunnels::tunnel_ready_handler),
        )
        .route(
            "/v1/tunnels/stopped",
            post(crate::tunnels::tunnel_stopped_handler),
        )
        .route(
            "/v1/tunnels/failed",
            post(crate::tunnels::tunnel_failed_handler),
        )
        .route(
            "/v1/subnet-routes",
            post(crate::tunnels::create_subnet_route_handler),
        )
        .route(
            "/v1/ssh-recordings",
            post(crate::ssh::upload_ssh_recording_handler),
        )
        .route(
            "/v1/ssh-sessions",
            get(crate::ssh::list_ssh_sessions_handler),
        )
        .route(
            "/v1/ssh-recordings/list",
            get(crate::ssh::list_ssh_recordings_handler),
        )
        .route(
            "/v1/ssh-recordings/{session_id}/cast",
            get(crate::ssh::get_ssh_recording_cast_handler),
        )
        .route(
            "/v1/ssh/auth/evaluate",
            post(crate::ssh_auth::evaluate_ssh_auth_handler),
        )
        .route(
            "/v1/ssh/auth/poll",
            post(crate::ssh_auth::poll_ssh_auth_handler),
        )
        .route(
            "/v1/ssh/auth/verify",
            post(crate::ssh_auth::verify_ssh_auth_handler),
        )
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let internal = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/ready", get(ready_handler))
        .with_state(state.clone());

    let public_listener = tokio::net::TcpListener::bind(&state.args.bind).await?;
    let internal_listener = tokio::net::TcpListener::bind(&state.args.internal_bind).await?;

    tracing::info!(bind = %state.args.bind, internal = %state.args.internal_bind, "listening");

    let public_srv = axum::serve(
        public_listener,
        public.into_make_service_with_connect_info::<SocketAddr>(),
    );
    let internal_srv = axum::serve(internal_listener, internal);

    tokio::try_join!(public_srv, internal_srv)?;
    Ok(())
}

// ---------- helpers ----------

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

// ---------- enroll ----------

const DEFAULT_NETWORK_NAME: &str = "default";
const DEFAULT_NETWORK_CIDR: &str = "10.7.0.0/24";
const DEFAULT_NETWORK_MTU: i32 = 1280;

async fn enroll_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<EnrollRequest>,
) -> Response {
    let outcome = enroll_inner(&state, req, Some(addr.ip())).await;
    match outcome {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => {
            state.metrics.http_request("enroll", code.as_str());
            err(code, &msg)
        }
    }
}

async fn enroll_status_handler(
    State(state): State<SharedState>,
    Json(req): Json<EnrollStatusRequest>,
) -> Response {
    match enroll_status_inner(&state, req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => err(code, &msg),
    }
}

async fn enroll_inner(
    state: &SharedState,
    req: EnrollRequest,
    public_ip: Option<std::net::IpAddr>,
) -> Result<EnrollResponse, (StatusCode, String)> {
    tuntun_common::validate_endpoint_id(&req.endpoint_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid endpoint_id".into()))?;
    if req.hostname.len() > 253 {
        return Err((StatusCode::BAD_REQUEST, "hostname too long".into()));
    }

    if let Some(meta) = &req.metadata
        && meta.get("direct_upgrade").is_some()
    {
        tracing::info!(
            endpoint_id = %req.endpoint_id,
            "direct → managed upgrade enroll"
        );
    }

    let token = req
        .enrollment_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let org_slug = req
        .organization_slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (organization_id, network_id, membership_status) = match (token, org_slug) {
        (Some(token), None) => {
            let (org_id, net_id) = consume_enrollment_token(state, token).await?;
            (org_id, net_id, "active".to_string())
        }
        (None, Some(slug)) => resolve_quick_enroll(state, slug, &req).await?,
        (Some(_), Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "provide either enrollment_token or organization_slug, not both".into(),
            ));
        }
        (None, None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "enrollment_token or organization_slug is required".into(),
            ));
        }
    };

    let device_type = req
        .metadata
        .as_ref()
        .and_then(|m| m.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("agent")
        .to_string();

    let expires_in = crate::device_handlers::resolve_enroll_expires_in(
        &state.pool,
        &organization_id,
        req.expires_in.as_deref(),
    )
    .await?;

    let resp = crate::register::register_device(
        &state.pool,
        &state.policy_key,
        crate::register::RegisterDeviceParams {
            endpoint_id: req.endpoint_id.clone(),
            organization_id,
            network_id,
            hostname: req.hostname.clone(),
            os: req.os.clone(),
            agent_version: req.agent_version.clone(),
            device_type,
            metadata: req.metadata.clone(),
            labels: req.labels.clone(),
            expires_in,
            public_ip,
            membership_status,
        },
    )
    .await?;

    state.metrics.http_request("enroll", "200");
    Ok(resp)
}

async fn consume_enrollment_token(
    state: &SharedState,
    token: &str,
) -> Result<(String, uuid::Uuid), (StatusCode, String)> {
    let token_hash = crate::enrollment::hash_token(token);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let row: Option<(String, uuid::Uuid)> = sqlx::query_as(
        "UPDATE enrollment_tokens et SET used_at = now() \
         FROM networks n \
         WHERE et.token_hash = $1 AND et.network_id = n.id \
           AND et.used_at IS NULL AND et.expires_at > now() \
         RETURNING n.organization_id, et.network_id",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let (organization_id, network_id) = row.ok_or_else(|| {
        state.metrics.auth_failure("bad_enroll_token");
        (
            StatusCode::UNAUTHORIZED,
            "invalid or expired enrollment token".into(),
        )
    })?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok((organization_id, network_id))
}

async fn resolve_quick_enroll(
    state: &SharedState,
    slug: &str,
    req: &EnrollRequest,
) -> Result<(String, uuid::Uuid, String), (StatusCode, String)> {
    if slug.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "organization_slug too long".into()));
    }

    let org: Option<(String, bool)> =
        sqlx::query_as("SELECT id, quick_enroll_enabled FROM organization WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let (organization_id, quick_enroll_enabled) = org.ok_or_else(|| {
        state.metrics.auth_failure("bad_quick_enroll");
        (StatusCode::NOT_FOUND, "organization not found".into())
    })?;

    if !quick_enroll_enabled {
        return Err((
            StatusCode::FORBIDDEN,
            "quick enroll is disabled for this organization".into(),
        ));
    }

    let network_id = resolve_quick_enroll_network(state, &organization_id, req).await?;
    Ok((organization_id, network_id, "pending".to_string()))
}

async fn resolve_quick_enroll_network(
    state: &SharedState,
    organization_id: &str,
    req: &EnrollRequest,
) -> Result<uuid::Uuid, (StatusCode, String)> {
    if let Some(network_id) = req.network_id {
        let exists: Option<(uuid::Uuid,)> =
            sqlx::query_as("SELECT id FROM networks WHERE id = $1 AND organization_id = $2")
                .bind(network_id)
                .bind(organization_id)
                .fetch_optional(&state.pool)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;
        return exists
            .map(|(id,)| id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "network not found".into()));
    }

    let name = req
        .network_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_NETWORK_NAME);

    if let Some((id,)) = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM networks WHERE organization_id = $1 AND name = $2",
    )
    .bind(organization_id)
    .bind(name)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?
    {
        return Ok(id);
    }

    if name != DEFAULT_NETWORK_NAME {
        return Err((StatusCode::NOT_FOUND, "network not found".into()));
    }

    ensure_default_network(&state.pool, organization_id).await
}

async fn ensure_default_network(
    pool: &sqlx::PgPool,
    organization_id: &str,
) -> Result<uuid::Uuid, (StatusCode, String)> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let existing: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM networks WHERE organization_id = $1 AND name = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(DEFAULT_NETWORK_NAME)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    if let Some((id,)) = existing {
        tx.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;
        return Ok(id);
    }

    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO networks (organization_id, name, cidr, mtu) \
         VALUES ($1, $2, $3::cidr, $4) \
         RETURNING id",
    )
    .bind(organization_id)
    .bind(DEFAULT_NETWORK_NAME)
    .bind(DEFAULT_NETWORK_CIDR)
    .bind(DEFAULT_NETWORK_MTU)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    Ok(id)
}

async fn enroll_status_inner(
    state: &SharedState,
    req: EnrollStatusRequest,
) -> Result<EnrollStatusResponse, (StatusCode, String)> {
    tuntun_common::validate_endpoint_id(&req.endpoint_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid endpoint_id".into()))?;

    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT d.organization_id, n.name, nm.status \
         FROM network_memberships nm \
         JOIN devices d ON d.endpoint_id = nm.endpoint_id \
         JOIN networks n ON n.id = nm.network_id \
         WHERE nm.endpoint_id = $1 AND nm.network_id = $2",
    )
    .bind(&req.endpoint_id)
    .bind(req.network_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {e}")))?;

    let Some((organization_id, network_name, status)) = row else {
        return Ok(EnrollStatusResponse::Rejected);
    };

    match status.as_str() {
        "pending" => Ok(EnrollStatusResponse::Pending {
            organization_id,
            network_id: req.network_id,
            network_name,
        }),
        "active" => {
            let snapshot = crate::snapshot::build_endpoint_snapshot(
                &state.pool,
                &state.policy_key,
                &req.endpoint_id,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("snapshot: {e}")))?;
            Ok(EnrollStatusResponse::Active {
                organization_id,
                network_id: req.network_id,
                network_name,
                snapshot: Box::new(snapshot),
            })
        }
        "suspended" => Err((
            StatusCode::FORBIDDEN,
            "device membership is suspended".into(),
        )),
        "expired" => Err((
            StatusCode::FORBIDDEN,
            "device expired; re-enroll required".into(),
        )),
        _ => Ok(EnrollStatusResponse::Rejected),
    }
}

async fn register_handler(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let parsed: RegisterRequest = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if parsed.endpoint_id != auth.endpoint_id {
        return err(StatusCode::BAD_REQUEST, "endpoint_id mismatch");
    }

    let _ = sqlx::query(crate::device_expiry_sql::SLIDE_ON_REGISTER)
        .bind(&auth.endpoint_id)
        .execute(&state.pool)
        .await;

    let metadata = parsed.metadata.unwrap_or_else(|| {
        serde_json::json!({
            "hostname": parsed.hostname,
            "agentVersion": parsed.agent_version,
            "reportedAt": chrono::Utc::now().to_rfc3339(),
        })
    });
    let pool = state.pool.clone();
    let endpoint_id = auth.endpoint_id.clone();
    let hostname = parsed.hostname.clone();
    let agent_version = parsed.agent_version.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::device_metadata::merge_device_metadata(
            &pool,
            &endpoint_id,
            &hostname,
            &agent_version,
            "",
            metadata,
        )
        .await
        {
            tracing::warn!(endpoint_id = %endpoint_id, error = %e, "metadata update failed");
        }
    });

    let snap = match crate::snapshot::build_endpoint_snapshot(
        &state.pool,
        &state.policy_key,
        &auth.endpoint_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("snapshot: {e}")),
    };

    state.metrics.http_request("register", "200");
    (StatusCode::OK, Json(snap)).into_response()
}

async fn poll_handler(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let parsed: PollRequest = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if parsed.endpoint_id != auth.endpoint_id {
        return err(StatusCode::BAD_REQUEST, "endpoint_id mismatch");
    }

    let _ = sqlx::query(crate::device_expiry_sql::SLIDE_ON_REGISTER)
        .bind(&auth.endpoint_id)
        .execute(&state.pool)
        .await;

    let snap: EndpointSnapshot = match crate::snapshot::build_endpoint_snapshot(
        &state.pool,
        &state.policy_key,
        &auth.endpoint_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("snapshot: {e}")),
    };

    state.metrics.http_request("poll", "200");
    (StatusCode::OK, Json(snap)).into_response()
}

async fn ws_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    let path = "/v1/ws".to_string();
    let method = "GET".to_string();

    let headers = req.headers().clone();
    let endpoint_id = match headers
        .get(tuntun_common::HDR_ENDPOINT_ID)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return err(StatusCode::UNAUTHORIZED, "missing X-Endpoint-Id"),
    };
    let ts: i64 = match headers
        .get(tuntun_common::HDR_TIMESTAMP)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
    {
        Some(t) => t,
        None => return err(StatusCode::UNAUTHORIZED, "missing X-Timestamp"),
    };
    let sig = match headers
        .get(tuntun_common::HDR_SIGNATURE)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => return err(StatusCode::UNAUTHORIZED, "missing X-Endpoint-Signature"),
    };

    if (chrono::Utc::now().timestamp() - ts).abs() > tuntun_common::MAX_SKEW_SECS {
        return err(StatusCode::UNAUTHORIZED, "stale timestamp");
    }
    let vk = match tuntun_common::signing::verifying_key_from_hex(&endpoint_id) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid pubkey"),
    };
    if tuntun_common::signing::verify(&vk, &method, &path, ts, &[], &sig).is_err() {
        return err(StatusCode::UNAUTHORIZED, "bad signature");
    }

    let device: Option<String> =
        match sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1")
            .bind(&endpoint_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };
    let organization_id = match device {
        Some(d) => d,
        None => return err(StatusCode::UNAUTHORIZED, "unknown device"),
    };

    match crate::device_expiry::is_device_expired(&state.pool, &endpoint_id).await {
        Ok(true) => {
            return err(StatusCode::FORBIDDEN, "device expired; re-enroll required");
        }
        Ok(false) => {}
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    }

    let network_ids: Vec<uuid::Uuid> = match sqlx::query_scalar(
        "SELECT network_id FROM network_memberships WHERE endpoint_id = $1 AND status = 'active'",
    )
    .bind(&endpoint_id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    if network_ids.is_empty() {
        return err(StatusCode::UNAUTHORIZED, "unknown device");
    }

    // Perform the actual upgrade.
    let upgrade = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    upgrade.on_upgrade(move |socket| async move {
        run_ws(
            state,
            socket,
            endpoint_id,
            organization_id,
            network_ids,
            Some(addr.ip()),
        )
        .await;
    })
}

async fn run_ws(
    state: SharedState,
    socket: WebSocket,
    endpoint_id: String,
    organization_id: String,
    network_ids: Vec<uuid::Uuid>,
    public_ip: Option<std::net::IpAddr>,
) {
    tracing::info!(%endpoint_id, ?public_ip, "ws connected");
    let _ = organization_id;

    if let Err(e) =
        crate::presence::mark_agent_connected(&state.pool, &endpoint_id, public_ip).await
    {
        tracing::warn!(?e, %endpoint_id, "failed to mark agent connected");
    }

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut rx = state
        .ws_hub
        .register(endpoint_id.clone(), network_ids.clone());

    if let Ok(snap) =
        crate::snapshot::build_endpoint_snapshot(&state.pool, &state.policy_key, &endpoint_id).await
    {
        let msg = ServerMsg::Snapshot(snap);
        if let Ok(txt) = serde_json::to_string(&msg) {
            let _ = ws_tx.send(Message::text(txt)).await;
        }
    }

    // Snapshot omits relay_auth_token; re-push OpenTunnel / StartServe so the
    // agent TunnelManager / ServeManager actually (re)start workloads.
    crate::reconnect::replay_endpoint_workloads(&state, &endpoint_id).await;

    let hub = state.ws_hub.clone();
    let ep_for_cleanup = endpoint_id.clone();

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(txt) = serde_json::to_string(&msg) else {
                continue;
            };
            if ws_tx.send(Message::text(txt)).await.is_err() {
                break;
            }
        }
    });

    // Ping loop + inbound reader.
    let pool = state.pool.clone();
    let ep = endpoint_id.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Text(txt) => {
                    if let Ok(cm) = serde_json::from_str::<ClientMsg>(txt.as_str()) {
                        match cm {
                            ClientMsg::Heartbeat { .. } => {
                                if let Err(e) = crate::presence::record_heartbeat(&pool, &ep).await
                                {
                                    tracing::warn!(?e, %ep, "heartbeat update failed");
                                }
                            }
                            ClientMsg::ServeReady { serve_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE serves SET status = 'active', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServeReady update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::ServeStopped { serve_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE serves SET status = 'stopped', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServeStopped update failed");
                                } else {
                                    let _ = sqlx::query(
                                        "DELETE FROM serve_sessions WHERE serve_id = $1::uuid",
                                    )
                                    .bind(&serve_id)
                                    .execute(&pool)
                                    .await;
                                    if let Err(e) =
                                        crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                            .await
                                    {
                                        tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                    }
                                }
                            }
                            ClientMsg::ServeFailed { serve_id, error } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE serves SET status = 'error', error_message = $3, \
                                     updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServeFailed update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::ServePeerJoined {
                                serve_id,
                                peer_endpoint_id,
                                peer_hostname,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO serve_sessions \
                                       (id, serve_id, peer_endpoint_id, peer_hostname, \
                                        connected_at, bytes_in, bytes_out, last_seen_at) \
                                     SELECT gen_random_uuid(), s.id, $2, $3, now(), 0, 0, now() \
                                     FROM serves s \
                                     WHERE s.id = $1::uuid AND s.endpoint_id = $4 \
                                     ON CONFLICT (serve_id, peer_endpoint_id) DO UPDATE SET \
                                       peer_hostname = COALESCE(EXCLUDED.peer_hostname, serve_sessions.peer_hostname), \
                                       connected_at = now(), \
                                       bytes_in = 0, \
                                       bytes_out = 0, \
                                       last_seen_at = now()",
                                )
                                .bind(&serve_id)
                                .bind(&peer_endpoint_id)
                                .bind(&peer_hostname)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServePeerJoined upsert failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::ServePeerLeft {
                                serve_id,
                                peer_endpoint_id,
                                bytes_in,
                                bytes_out,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "DELETE FROM serve_sessions ss \
                                     USING serves s \
                                     WHERE ss.serve_id = s.id \
                                       AND s.id = $1::uuid \
                                       AND s.endpoint_id = $2 \
                                       AND ss.peer_endpoint_id = $3",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .bind(&peer_endpoint_id)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(
                                        ?e,
                                        %serve_id,
                                        bytes_in,
                                        bytes_out,
                                        "ServePeerLeft delete failed"
                                    );
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::TunnelReady { tunnel_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'active', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelReady update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::TunnelStopped { tunnel_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'stopped', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelStopped update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::TunnelFailed { tunnel_id, error } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'error', error_message = $3, \
                                     updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelFailed update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::SshSessionStarted {
                                session_id,
                                src_endpoint_id,
                                target_user,
                                src_hostname,
                                recorded,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO ssh_sessions \
                                       (id, organization_id, network_id, src_endpoint_id, dst_endpoint_id, \
                                        src_hostname, dst_hostname, target_user, status, recorded, started_at) \
                                     SELECT $1::uuid, d.organization_id, nm.network_id, $2, $3, \
                                            $4, COALESCE(NULLIF(d.metadata->>'hostname', ''), left(d.endpoint_id, 8)), \
                                            $5, 'active', $6, now() \
                                     FROM devices d \
                                     JOIN network_memberships nm ON nm.endpoint_id = d.endpoint_id \
                                       AND nm.status = 'active' \
                                     WHERE d.endpoint_id = $3 \
                                     LIMIT 1 \
                                     ON CONFLICT (id) DO NOTHING",
                                )
                                .bind(&session_id)
                                .bind(&src_endpoint_id)
                                .bind(&ep)
                                .bind(&src_hostname)
                                .bind(&target_user)
                                .bind(recorded)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %session_id, "SshSessionStarted insert failed");
                                }
                            }
                            ClientMsg::SshSessionEnded {
                                session_id,
                                status,
                                duration_ms,
                            } => {
                                let status = if status.is_empty() {
                                    "ended".to_string()
                                } else {
                                    status
                                };
                                if let Err(e) = sqlx::query(
                                    "UPDATE ssh_sessions \
                                     SET status = $2, ended_at = now(), duration_ms = $3 \
                                     WHERE id = $1::uuid AND dst_endpoint_id = $4",
                                )
                                .bind(&session_id)
                                .bind(&status)
                                .bind(duration_ms.map(|v| v as i32))
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %session_id, "SshSessionEnded update failed");
                                }
                            }
                            ClientMsg::SshRecordingSaved {
                                session_id,
                                recorder_endpoint_id: _,
                                duration_ms,
                                byte_size: _,
                                content_sha256: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE ssh_sessions SET recorded = true, \
                                     duration_ms = COALESCE($2, duration_ms) \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&session_id)
                                .bind(duration_ms.map(|v| v as i32))
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(
                                        ?e,
                                        %session_id,
                                        "SshRecordingSaved update failed"
                                    );
                                }
                            }
                            ClientMsg::TransferOffer {
                                transfer_id,
                                sender_endpoint_id,
                                receiver_endpoint_id,
                                file_name,
                                size,
                                blake3_hash,
                                status,
                                message,
                            } => {
                                let status = if status.is_empty() {
                                    "offered".to_string()
                                } else {
                                    status
                                };
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO file_transfers \
                                       (id, organization_id, network_id, sender_endpoint_id, \
                                        receiver_endpoint_id, file_name, size_bytes, blake3_hash, \
                                        status, progress_pct, bytes_transferred, message, created_at) \
                                     SELECT $1::uuid, d.organization_id, nm.network_id, $2, $3, \
                                            $4, $5, $6, $7, 0, 0, $8, now() \
                                     FROM devices d \
                                     JOIN network_memberships nm ON nm.endpoint_id = d.endpoint_id \
                                       AND nm.status = 'active' \
                                     WHERE d.endpoint_id = $2 \
                                     LIMIT 1 \
                                     ON CONFLICT (id) DO UPDATE SET \
                                       status = EXCLUDED.status, \
                                       receiver_endpoint_id = COALESCE(EXCLUDED.receiver_endpoint_id, file_transfers.receiver_endpoint_id), \
                                       message = COALESCE(EXCLUDED.message, file_transfers.message)",
                                )
                                .bind(&transfer_id)
                                .bind(&sender_endpoint_id)
                                .bind(&receiver_endpoint_id)
                                .bind(&file_name)
                                .bind(size as i64)
                                .bind(&blake3_hash)
                                .bind(&status)
                                .bind(&message)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferOffer upsert failed");
                                }
                            }
                            ClientMsg::TransferProgress {
                                transfer_id,
                                percent,
                                bytes_transferred,
                                bytes_total: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = 'transferring', \
                                         progress_pct = $2, \
                                         bytes_transferred = $3 \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(percent.round() as i32)
                                .bind(bytes_transferred as i64)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferProgress update failed");
                                }
                            }
                            ClientMsg::TransferComplete {
                                transfer_id,
                                inbox_path,
                                duration_ms: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = 'completed', progress_pct = 100, \
                                         inbox_path = $2, completed_at = now() \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(&inbox_path)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferComplete update failed");
                                }
                            }
                            ClientMsg::TransferFailed {
                                transfer_id,
                                error,
                                rejected,
                            } => {
                                let status = if rejected { "rejected" } else { "failed" };
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = $2, error = $3, completed_at = now() \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(status)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferFailed update failed");
                                }
                            }
                            ClientMsg::Hello { .. } | ClientMsg::Pong { .. } => {}
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    hub.unregister(&ep_for_cleanup, &network_ids);
    if let Err(e) = crate::presence::mark_agent_disconnected(&state.pool, &ep_for_cleanup).await {
        tracing::warn!(?e, %ep_for_cleanup, "failed to mark agent disconnected");
    }
    tracing::info!(%ep_for_cleanup, "ws disconnected");
}

async fn metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

async fn ready_handler(State(state): State<SharedState>) -> impl IntoResponse {
    // Cheap ping to DB.
    let ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    if ok {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "db down")
    }
}

use axum::extract::FromRequest;

#[allow(dead_code)]
fn _touch(_s: Arc<AppState>) {}
