//! Bootstrap-only Local Management API (no mesh / CoreNode yet).
//!
//! Used while the agent is idle waiting for create / enroll / join so the
//! Windows service can leave StartPending and the CLI can call lifecycle APIs.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tunnet_common::local_api::permissions::{EVENTS_READ, LIFECYCLE, STATUS_READ};
use tunnet_common::local_api::{
    ApiError, ApiErrorCode, AuthLoginRequest, LocalEnrollRequest, MetaInfo, NetworkCreateRequest,
    NetworkJoinRequest, NetworkLeaveRequest, NetworkUpgradeRequest, NodeSummary, OkResponse,
    ResetRequest, UpdateRequest, ValidateConfigRequest,
};

use super::auth::PeerIdentity;
use super::bootstrap::BootstrapOps;
use super::handlers;

#[derive(Clone)]
pub struct BootstrapApiState {
    pub bootstrap: Arc<dyn BootstrapOps>,
    pub daemon_version: String,
    pub events: tokio::sync::broadcast::Sender<tunnet_common::local_api::LocalEvent>,
}

type ApiState = BootstrapApiState;

pub fn bootstrap_app(state: ApiState) -> Router {
    Router::new()
        .route("/v1/meta", get(idle_meta))
        .route("/v1/node", get(idle_node))
        .route("/v1/events", get(idle_events))
        .route("/v1/enroll", post(enroll))
        .route("/v1/networks", post(network_create))
        .route("/v1/networks/join", post(network_join))
        .route("/v1/networks/leave", post(network_leave))
        .route("/v1/networks/upgrade", post(network_upgrade))
        .route("/v1/reset", post(reset))
        .route("/v1/config/validate", post(validate_config))
        .route("/v1/auth/login", post(auth_login))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/update", get(update_check).post(update))
        .with_state(state)
}

fn api_status(code: &ApiErrorCode) -> StatusCode {
    match code {
        ApiErrorCode::DaemonNotRunning => StatusCode::SERVICE_UNAVAILABLE,
        ApiErrorCode::DataPlaneDown => StatusCode::SERVICE_UNAVAILABLE,
        ApiErrorCode::NotEnrolled => StatusCode::CONFLICT,
        ApiErrorCode::NotFound => StatusCode::NOT_FOUND,
        ApiErrorCode::Denied => StatusCode::FORBIDDEN,
        ApiErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ApiErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

struct ApiErrorResponse(ApiError);

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        let status = api_status(&self.0.code);
        (status, Json(self.0)).into_response()
    }
}

impl From<ApiError> for ApiErrorResponse {
    fn from(e: ApiError) -> Self {
        Self(e)
    }
}

type ApiResult<T> = Result<T, ApiErrorResponse>;

async fn idle_meta(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<MetaInfo>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(handlers::idle_meta(&state.daemon_version, &peer)))
}

async fn idle_node(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<NodeSummary>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(
        state
            .bootstrap
            .observe_mesh()
            .map(|obs| handlers::node_summary_from_observation(&state.daemon_version, &obs))
            .unwrap_or_else(|| handlers::idle_node_summary(&state.daemon_version)),
    ))
}

async fn idle_events(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>> {
    peer.require_cap(EVENTS_READ)?;
    let rx = state.events.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let data = serde_json::to_string(&ev).ok()?;
                    return Some((Ok(Event::default().data(data)), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn enroll(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<LocalEnrollRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.enroll(body).await?))
}

async fn network_create(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkCreateRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.network_create(body).await?))
}

async fn network_join(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkJoinRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.network_join(body).await?))
}

async fn network_leave(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkLeaveRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.network_leave(body).await?))
}

async fn network_upgrade(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkUpgradeRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.network_upgrade(body).await?))
}

async fn reset(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<ResetRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(LIFECYCLE)?;
    Ok(Json(state.bootstrap.reset(body).await?))
}

async fn validate_config(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<ValidateConfigRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(state.bootstrap.validate_config(body).await?))
}

async fn auth_login(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<AuthLoginRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(state.bootstrap.auth_login(body).await?))
}

async fn auth_logout(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(state.bootstrap.auth_logout().await?))
}

async fn update_check(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<tunnet_common::local_api::CoreUpdateStatus>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(state.bootstrap.update_check().await?))
}

async fn update(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<UpdateRequest>,
) -> ApiResult<Json<tunnet_common::local_api::CoreUpdateStatus>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.update(body).await?))
}
