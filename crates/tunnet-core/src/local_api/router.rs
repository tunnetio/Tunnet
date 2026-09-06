//! Axum router for the Local Management API (`/v1/...`).

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tunnet_common::local_api::permissions::{
    DATA_PLANE_WRITE, DIAG_READ, DNS_READ, EVENTS_READ, FIREWALL_WRITE, NETWORK_ADMIT,
    NETWORK_INVITE, POLICY_WRITE, ROUTES_READ, SEND, SERVE, SSH, STATUS_READ, TUNNEL,
};
use tunnet_common::local_api::{
    ApiError, ApiErrorCode, AuthLoginRequest, DataPlaneStatus, DeviceExpiryRequest,
    DeviceLabelDeleteRequest, DeviceLabelPatchRequest, DeviceLabelRequest, DeviceTagAddRequest,
    DeviceTagRemoveRequest, DirectConnectContactRequest, DirectConnectPendingResponse,
    DirectConnectRequest, DirectContactResponse, DirectFirewallAddRequest,
    DirectFirewallPendingResponse, DirectFirewallRemoveRequest, DirectFirewallResponse,
    DirectInviteRequest, DirectInviteResponse, DirectKeepAliveRequest, DirectNetworkRequest,
    DirectPendingResponse, DirectPolicyResponse, DirectPolicySetRequest, JsonPayload,
    LocalEnrollRequest, MetaInfo, NetworkCreateRequest, NetworkJoinRequest, NetworkLeaveRequest,
    NetworkUpgradeRequest, NetworksResponse, NodeSummary, OkResponse, PeersResponse,
    PolicyOpRequest, PostureCheckRequest, ResetRequest, RouteAddRequest, RouteAddedResponse,
    SendAcceptRequest, SendFileRequest, SendRejectRequest, SendSetConfigRequest, ServeStartRequest,
    ServesResponse, SshAuthPollRequest, SshAuthPollResponse, SshCastResponse, SshRecordingsParams,
    SshRecordingsResponse, SshSessionsParams, SshSessionsResponse, TransfersResponse,
    TunnelOffRequest, TunnelStartRequest, TunnelsResponse, UpdateRequest, ValidateConfigRequest,
};

use super::auth::PeerIdentity;
use super::handlers::{self, map_anyhow, result_ok};
use super::state::LocalApiState;

type ApiState = Arc<LocalApiState>;

pub fn app(state: ApiState) -> Router {
    Router::new()
        .route("/v1/meta", get(meta))
        .route("/v1/node", get(node_summary))
        .route("/v1/networks", get(networks_list).post(network_create))
        .route("/v1/networks/{network_id}", get(network_get))
        .route("/v1/networks/{network_id}/peers", get(network_peers))
        .route("/v1/networks/{network_id}/routes", get(network_routes))
        .route(
            "/v1/networks/{network_id}/join-requests",
            get(network_join_requests),
        )
        .route(
            "/v1/networks/{network_id}/join-requests/{peer_id}/accept",
            post(network_join_accept),
        )
        .route(
            "/v1/networks/{network_id}/join-requests/{peer_id}/deny",
            post(network_join_deny),
        )
        .route(
            "/v1/networks/{network_id}/firewall",
            get(network_firewall_show),
        )
        .route("/v1/events", get(events_stream))
        .route("/v1/dns", get(dns))
        .route("/v1/routes", get(routes_list).post(routes_add))
        .route("/v1/ping/{peer}", get(ping))
        .route("/v1/diag", get(diag))
        .route("/v1/acl/denies", get(acl_denies))
        .route("/v1/netcheck", get(netcheck))
        .route("/v1/reload", post(reload))
        .route("/v1/data-plane", get(data_plane_status))
        .route("/v1/data-plane/up", post(data_plane_up))
        .route("/v1/data-plane/down", post(data_plane_down))
        .route("/v1/serves", get(serves_list).post(serves_start))
        .route("/v1/serves/{port}", delete(serves_off))
        .route("/v1/tunnels", get(tunnels_list).post(tunnels_start))
        .route("/v1/tunnels/{port}", delete(tunnels_off))
        .route("/v1/ssh/sessions", get(ssh_sessions))
        .route("/v1/ssh/recordings", get(ssh_recordings))
        .route("/v1/ssh/recordings/{session_id}/cast", get(ssh_cast))
        .route("/v1/ssh/auth/poll", post(ssh_auth_poll))
        .route("/v1/transfers", get(transfers_list))
        .route("/v1/transfers/send", post(transfers_send))
        .route("/v1/transfers/history", get(transfers_history))
        .route("/v1/transfers/{id}/accept", post(transfers_accept))
        .route("/v1/transfers/{id}/reject", post(transfers_reject))
        .route("/v1/send/config", get(send_config).put(send_set_config))
        .route("/v1/direct/invites", post(direct_invite))
        .route("/v1/direct/requests", get(direct_requests))
        .route("/v1/direct/requests/{peer_id}/accept", post(direct_accept))
        .route("/v1/direct/requests/{peer_id}/deny", post(direct_deny))
        .route("/v1/direct/peers/{peer_id}/kick", post(direct_kick))
        .route("/v1/direct/firewall", get(direct_firewall_show))
        .route("/v1/direct/firewall/off", post(direct_firewall_off))
        .route("/v1/direct/firewall/rules", post(direct_firewall_add))
        .route(
            "/v1/direct/firewall/rules/{index}",
            delete(direct_firewall_remove),
        )
        .route("/v1/direct/firewall/reset", post(direct_firewall_reset))
        .route(
            "/v1/direct/firewall/conntrack/flush",
            post(direct_firewall_flush),
        )
        .route("/v1/direct/firewall/pending", get(direct_firewall_pending))
        .route(
            "/v1/direct/firewall/pending/accept",
            post(direct_firewall_accept),
        )
        .route(
            "/v1/direct/firewall/pending/reject",
            post(direct_firewall_reject),
        )
        .route(
            "/v1/direct/policy",
            get(direct_policy_show)
                .put(direct_policy_set)
                .delete(direct_policy_clear),
        )
        .route("/v1/direct/keep-alive", post(direct_keep_alive))
        .route("/v1/direct/connect", post(direct_connect))
        .route("/v1/direct/connect/allow", post(direct_connect_allow))
        .route("/v1/direct/connect/pending", get(direct_connect_pending))
        .route(
            "/v1/direct/connect/pending/{id}/accept",
            post(direct_connect_accept),
        )
        .route(
            "/v1/direct/connect/pending/{id}/deny",
            post(direct_connect_deny),
        )
        .route("/v1/direct/connect/rotate", post(direct_connect_rotate))
        .route("/v1/enroll", post(enroll))
        .route("/v1/networks/join", post(network_join))
        .route("/v1/networks/leave", post(network_leave))
        .route("/v1/networks/upgrade", post(network_upgrade))
        .route("/v1/reset", post(reset))
        .route("/v1/config/validate", post(validate_config))
        .route("/v1/auth/login", post(auth_login))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/update", get(update_check).post(update))
        .route("/v1/device/labels", post(device_set_labels))
        .route("/v1/device/labels/patch", post(device_patch_labels))
        .route("/v1/device/labels/delete", post(device_delete_label))
        .route("/v1/device/tags", post(device_add_tag))
        .route("/v1/device/tags/remove", post(device_remove_tag))
        .route("/v1/device/expiry", post(device_set_expiry))
        .route("/v1/device", get(device_info))
        .route("/v1/posture", get(posture_status))
        .route("/v1/posture/check", post(posture_check))
        .route("/v1/policy", post(policy_op))
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

async fn enroll(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<LocalEnrollRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.enroll(body).await?))
}

async fn network_create(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkCreateRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.network_create(body).await?))
}

async fn network_join(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkJoinRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.network_join(body).await?))
}

async fn network_leave(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkLeaveRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.network_leave(body).await?))
}

async fn network_upgrade(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<NetworkUpgradeRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
    Ok(Json(state.bootstrap.network_upgrade(body).await?))
}

async fn reset(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<ResetRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_elevated()?;
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

async fn device_set_labels(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceLabelRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_set_labels(body).await?))
}

async fn device_patch_labels(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceLabelPatchRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_patch_labels(body).await?))
}

async fn device_delete_label(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceLabelDeleteRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_delete_label(body).await?))
}

async fn device_add_tag(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceTagAddRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_add_tag(body).await?))
}

async fn device_remove_tag(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceTagRemoveRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_remove_tag(body).await?))
}

async fn device_set_expiry(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DeviceExpiryRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    Ok(Json(state.bootstrap.device_set_expiry(body).await?))
}

async fn device_info(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<JsonPayload>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(state.bootstrap.device_info().await?))
}

async fn posture_status(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<JsonPayload>> {
    peer.require_cap(DIAG_READ)?;
    Ok(Json(state.bootstrap.posture_status().await?))
}

async fn posture_check(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<PostureCheckRequest>,
) -> ApiResult<Json<JsonPayload>> {
    peer.require_cap(DIAG_READ)?;
    Ok(Json(state.bootstrap.posture_check(body).await?))
}

async fn policy_op(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<PolicyOpRequest>,
) -> ApiResult<Json<JsonPayload>> {
    peer.require_cap(POLICY_WRITE)?;
    Ok(Json(state.bootstrap.policy_op(body).await?))
}

async fn meta(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<MetaInfo>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(handlers::build_meta(&state, &peer)))
}

async fn node_summary(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<NodeSummary>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(handlers::build_node_summary(&state)))
}

async fn networks_list(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<NetworksResponse>> {
    peer.require_cap(STATUS_READ)?;
    let node = handlers::build_node_summary(&state);
    Ok(Json(NetworksResponse {
        networks: node.networks,
    }))
}

async fn network_get(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(network_id): Path<String>,
) -> ApiResult<Json<tunnet_common::local_api::NetworkSummary>> {
    peer.require_cap(STATUS_READ)?;
    let id = handlers::parse_network_id(&network_id)?;
    Ok(Json(handlers::build_network_summary(&state, id)?))
}

async fn network_peers(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(network_id): Path<String>,
) -> ApiResult<Json<PeersResponse>> {
    peer.require_cap(STATUS_READ)?;
    let id = handlers::parse_network_id(&network_id)?;
    Ok(Json(PeersResponse {
        peers: handlers::peer_summaries(&state, Some(id)),
    }))
}

async fn network_routes(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(network_id): Path<String>,
) -> ApiResult<Json<tunnet_common::local_api::RoutesInfo>> {
    peer.require_cap(ROUTES_READ)?;
    let id = handlers::parse_network_id(&network_id)?;
    Ok(Json(handlers::build_routes(&state, id)))
}

async fn network_join_requests(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(network_id): Path<String>,
) -> ApiResult<Json<DirectPendingResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let id = handlers::parse_network_id(&network_id)?;
    let requests = handlers::direct_requests_for_network(&state, id).map_err(map_anyhow)?;
    Ok(Json(DirectPendingResponse { requests }))
}

async fn network_join_accept(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path((network_id, peer_id)): Path<(String, String)>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let id = handlers::parse_network_id(&network_id)?;
    let message = handlers::direct_accept_for_network(&state, id, &peer_id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn network_join_deny(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path((network_id, peer_id)): Path<(String, String)>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let id = handlers::parse_network_id(&network_id)?;
    let message = handlers::direct_deny_for_network(&state, id, &peer_id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn network_firewall_show(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(network_id): Path<String>,
) -> ApiResult<Json<DirectFirewallResponse>> {
    peer.require_cap(STATUS_READ)?;
    let id = handlers::parse_network_id(&network_id)?;
    let info = handlers::direct_firewall_for_network(&state, id).map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn events_stream(
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

async fn dns(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<tunnet_common::local_api::DnsStatusInfo>> {
    peer.require_cap(DNS_READ)?;
    Ok(Json(handlers::build_dns_status(&state)))
}

#[derive(Debug, serde::Deserialize)]
struct RoutesQuery {
    network_id: Option<String>,
}

async fn routes_list(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<RoutesQuery>,
) -> ApiResult<Json<tunnet_common::local_api::RoutesInfo>> {
    peer.require_cap(ROUTES_READ)?;
    let network_id = if let Some(id) = q.network_id {
        handlers::parse_network_id(&id)?
    } else {
        state.node.persisted.primary_network_id().ok_or_else(|| {
            handlers::api_err(
                ApiErrorCode::InvalidRequest,
                "multiple networks joined; pass ?network_id=<uuid>",
            )
        })?
    };
    Ok(Json(handlers::build_routes(&state, network_id)))
}

async fn routes_add(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<RouteAddRequest>,
) -> ApiResult<Json<RouteAddedResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    let net: ipnet::Ipv4Net = body.cidr.parse().map_err(|e| {
        handlers::api_err(ApiErrorCode::InvalidRequest, format!("invalid cidr: {e}"))
    })?;
    let cidr = handlers::advertise_subnet_route(&state, &net.to_string(), body.description)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(RouteAddedResponse { cidr }))
}

async fn ping(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(peer_name): Path<String>,
    Query(q): Query<PingQuery>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>> {
    peer.require_cap(DIAG_READ)?;
    let count = q.count.unwrap_or(4);
    let interval_ms = q.interval_ms.unwrap_or(1000);
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(handlers::run_ping(peer_name, count, interval_ms, state, tx));

    let stream = ReceiverStream::new(rx).filter_map(|item| match item {
        Ok(ev) => {
            let data = serde_json::to_string(&ev).ok()?;
            Some(Ok(Event::default().data(data)))
        }
        Err(err) => {
            let data = serde_json::to_string(&err).ok()?;
            Some(Ok(Event::default().event("error").data(data)))
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Debug, serde::Deserialize)]
struct PingQuery {
    count: Option<u32>,
    interval_ms: Option<u64>,
}

async fn diag(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<tunnet_common::local_api::DiagInfo>> {
    peer.require_cap(DIAG_READ)?;
    Ok(Json(handlers::build_diag(&state).await))
}

async fn acl_denies(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<serde_json::Value>> {
    peer.require_cap(DIAG_READ)?;
    Ok(Json(serde_json::json!({
        "denies": state.node.acl.recent_denies(),
    })))
}

async fn netcheck(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<tunnet_common::local_api::NetcheckInfo>> {
    peer.require_cap(DIAG_READ)?;
    Ok(Json(handlers::build_netcheck(&state).await))
}

async fn reload(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    let message = handlers::reload_config(&state).await.map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn data_plane_status(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<DataPlaneStatus>> {
    peer.require_cap(STATUS_READ)?;
    Ok(Json(DataPlaneStatus {
        up: state.data_plane.is_up(),
    }))
}

async fn data_plane_up(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    state.data_plane.bring_up().await.map_err(map_anyhow)?;
    Ok(Json(result_ok("data plane up")))
}

async fn data_plane_down(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    state.data_plane.bring_down().await.map_err(map_anyhow)?;
    Ok(Json(result_ok("data plane down")))
}

async fn serves_list(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<ServesResponse>> {
    peer.require_cap(SERVE)?;
    Ok(Json(ServesResponse {
        serves: state.serves.list(),
    }))
}

async fn serves_start(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<ServeStartRequest>,
) -> ApiResult<Json<tunnet_common::local_api::ServeInfo>> {
    peer.require_cap(SERVE)?;
    let info = handlers::start_serve(
        &state,
        body.port,
        &body.protocol,
        body.certificate_pem.as_deref(),
        body.private_key_pem.as_deref(),
        body.internal_hostname.as_deref(),
        body.serve_id,
        body.access_mode,
        body.allowed_tags,
        body.allowed_endpoint_ids,
    )
    .await
    .map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn serves_off(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(port): Path<u16>,
) -> ApiResult<Json<tunnet_common::local_api::ServeInfo>> {
    peer.require_cap(SERVE)?;
    let info = state.serves.stop(port).await.map_err(map_anyhow)?;
    if let Some(tx) = state.serves.client_tx() {
        let _ = tx.try_send(tunnet_common::ws::ClientMsg::ServeStopped {
            serve_id: info.id.clone(),
        });
    }
    Ok(Json(info))
}

async fn tunnels_list(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<TunnelsResponse>> {
    peer.require_cap(TUNNEL)?;
    Ok(Json(TunnelsResponse {
        tunnels: state.tunnels.list(),
    }))
}

async fn tunnels_start(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<TunnelStartRequest>,
) -> ApiResult<Json<tunnet_common::local_api::TunnelInfo>> {
    peer.require_cap(TUNNEL)?;
    let info = handlers::start_tunnel(
        &state,
        body.port,
        &body.protocol,
        body.edge.as_deref(),
        body.subdomain.as_deref(),
        body.inspect,
        body.inspect_addr.as_deref(),
    )
    .await
    .map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn tunnels_off(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(port): Path<u16>,
) -> ApiResult<Json<tunnet_common::local_api::TunnelInfo>> {
    peer.require_cap(TUNNEL)?;
    let _ = TunnelOffRequest { port };
    let info = handlers::stop_tunnel(&state, port)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn ssh_sessions(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<SshSessionsParams>,
) -> ApiResult<Json<SshSessionsResponse>> {
    peer.require_cap(SSH)?;
    let sessions = handlers::list_ssh_sessions(&state, q.limit, q.status.as_deref())
        .await
        .map_err(map_anyhow)?;
    Ok(Json(SshSessionsResponse { sessions }))
}

async fn ssh_recordings(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<SshRecordingsParams>,
) -> ApiResult<Json<SshRecordingsResponse>> {
    peer.require_cap(SSH)?;
    let recordings = handlers::list_ssh_recordings(&state, q.limit)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(SshRecordingsResponse { recordings }))
}

async fn ssh_cast(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<SshCastResponse>> {
    peer.require_cap(SSH)?;
    let (session_id, cast_text, content_sha256) = handlers::get_ssh_cast(&state, &session_id)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(SshCastResponse {
        session_id,
        cast_text,
        content_sha256,
    }))
}

async fn ssh_auth_poll(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<SshAuthPollRequest>,
) -> ApiResult<Json<SshAuthPollResponse>> {
    peer.require_cap(SSH)?;
    let (status, proof_token) = handlers::poll_ssh_auth(&state, &body.challenge_token)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(SshAuthPollResponse {
        status,
        proof_token,
    }))
}

async fn transfers_list(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<TransfersResponse>> {
    peer.require_cap(SEND)?;
    let mut transfers: Vec<_> = state
        .send
        .list_active()
        .into_iter()
        .chain(state.send.list_pending())
        .map(handlers::transfer_info)
        .collect();
    transfers.sort_by(|a, b| a.transfer_id.cmp(&b.transfer_id));
    transfers.dedup_by(|a, b| a.transfer_id == b.transfer_id);
    Ok(Json(TransfersResponse { transfers }))
}

async fn transfers_send(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<SendFileRequest>,
) -> ApiResult<Json<TransfersResponse>> {
    peer.require_cap(SEND)?;
    let records = state
        .send
        .send_file(std::path::Path::new(&body.path), &body.target, body.message)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(TransfersResponse {
        transfers: records.into_iter().map(handlers::transfer_info).collect(),
    }))
}

async fn transfers_history(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<TransfersResponse>> {
    peer.require_cap(SEND)?;
    Ok(Json(TransfersResponse {
        transfers: state
            .send
            .list_history()
            .into_iter()
            .map(handlers::transfer_info)
            .collect(),
    }))
}

async fn transfers_accept(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(_body): Json<Option<SendAcceptRequest>>,
) -> ApiResult<Json<tunnet_common::local_api::TransferInfo>> {
    peer.require_cap(SEND)?;
    let r = state.send.accept_pending(&id).await.map_err(map_anyhow)?;
    Ok(Json(handlers::transfer_info(r)))
}

async fn transfers_reject(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<Option<SendRejectRequest>>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(SEND)?;
    let reason = body.and_then(|b| b.reason);
    state
        .send
        .reject_pending(&id, reason)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok("rejected")))
}

async fn send_config(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<tunnet_common::local_api::SendConfigInfo>> {
    peer.require_cap(SEND)?;
    let cfg = state.send.config();
    Ok(Json(tunnet_common::local_api::SendConfigInfo {
        consent: cfg.consent.as_str().into(),
        inbox_path: cfg.inbox_path.display().to_string(),
        pin_blobs: cfg.pin_blobs,
    }))
}

async fn send_set_config(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<SendSetConfigRequest>,
) -> ApiResult<Json<tunnet_common::local_api::SendConfigInfo>> {
    peer.require_cap(SEND)?;
    let mut cfg = state.send.config();
    if let Some(c) = body.consent {
        match tunnet_common::send::SendConsentMode::parse(&c) {
            Some(m) => cfg.consent = m,
            None => {
                return Err(handlers::api_err(
                    ApiErrorCode::InvalidRequest,
                    format!("invalid consent mode: {c}"),
                )
                .into());
            }
        }
    }
    if let Some(p) = body.inbox_path {
        cfg.inbox_path = std::path::PathBuf::from(p);
    }
    if let Some(p) = body.pin_blobs {
        cfg.pin_blobs = p;
    }
    state.send.set_config(cfg.clone());
    Ok(Json(tunnet_common::local_api::SendConfigInfo {
        consent: cfg.consent.as_str().into(),
        inbox_path: cfg.inbox_path.display().to_string(),
        pin_blobs: cfg.pin_blobs,
    }))
}

async fn direct_invite(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectInviteRequest>,
) -> ApiResult<Json<DirectInviteResponse>> {
    peer.require_cap(NETWORK_INVITE)?;
    let code = handlers::direct_invite(
        &state,
        body.network.as_deref(),
        body.reusable,
        &body.expires,
    )
    .map_err(map_anyhow)?;
    Ok(Json(DirectInviteResponse { code }))
}

async fn direct_requests(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<DirectPendingResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let requests = handlers::direct_requests(&state, q.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(DirectPendingResponse { requests }))
}

async fn direct_accept(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(peer_id): Path<String>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let message =
        handlers::direct_accept(&state, q.network.as_deref(), &peer_id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_deny(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(peer_id): Path<String>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let message =
        handlers::direct_deny(&state, q.network.as_deref(), &peer_id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_kick(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(peer_id): Path<String>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let message = handlers::direct_kick(&state, q.network.as_deref(), &peer_id)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_show(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<DirectFirewallResponse>> {
    peer.require_cap(STATUS_READ)?;
    let info = handlers::direct_firewall_show(&state, q.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn direct_firewall_off(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message =
        handlers::direct_firewall_off(&state, body.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_add(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectFirewallAddRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message = handlers::direct_firewall_add(
        &state,
        body.network.as_deref(),
        &body.direction,
        &body.action,
        &body.protocol,
        body.port.as_deref(),
        body.peer,
    )
    .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_remove(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(index): Path<usize>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let _ = DirectFirewallRemoveRequest {
        network: q.network.clone(),
        index,
    };
    let message = handlers::direct_firewall_remove(&state, q.network.as_deref(), index)
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_reset(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message =
        handlers::direct_firewall_reset(&state, body.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_flush(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message =
        handlers::direct_firewall_flush(&state, body.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_pending(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<DirectFirewallPendingResponse>> {
    peer.require_cap(STATUS_READ)?;
    let info =
        handlers::direct_firewall_pending(&state, q.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn direct_firewall_accept(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message =
        handlers::direct_firewall_accept(&state, body.network.as_deref()).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_firewall_reject(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(FIREWALL_WRITE)?;
    let message = handlers::direct_firewall_reject_suggestion(&state, body.network.as_deref())
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_policy_show(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<DirectPolicyResponse>> {
    peer.require_cap(STATUS_READ)?;
    let info = handlers::direct_policy_show(&state, q.network.as_deref())
        .await
        .map_err(map_anyhow)?;
    Ok(Json(info))
}

async fn direct_policy_set(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectPolicySetRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(POLICY_WRITE)?;
    let message = handlers::direct_policy_set(&state, body.network.as_deref(), &body.toml)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_policy_clear(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Query(q): Query<DirectNetworkRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(POLICY_WRITE)?;
    let message = handlers::direct_policy_clear(&state, q.network.as_deref())
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_keep_alive(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectKeepAliveRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(DATA_PLANE_WRITE)?;
    let message =
        handlers::direct_keep_alive(&state, &body.hostname, body.enable).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_connect(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectConnectRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(STATUS_READ)?;
    let message = crate::direct::connect::request_connect(&state, &body.contact_id)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_connect_allow(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Json(body): Json<DirectConnectContactRequest>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(STATUS_READ)?;
    let message =
        crate::direct::connect::allow_contact(&state, &body.contact_id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_connect_pending(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<DirectConnectPendingResponse>> {
    peer.require_cap(STATUS_READ)?;
    let requests = crate::direct::connect::list_pending(&state).map_err(map_anyhow)?;
    Ok(Json(DirectConnectPendingResponse { requests }))
}

async fn direct_connect_accept(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let message = crate::direct::connect::accept_pending(&state, &id)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_connect_deny(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<OkResponse>> {
    peer.require_cap(NETWORK_ADMIT)?;
    let message = crate::direct::connect::deny_pending(&state, &id).map_err(map_anyhow)?;
    Ok(Json(result_ok(message)))
}

async fn direct_connect_rotate(
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<ApiState>,
) -> ApiResult<Json<DirectContactResponse>> {
    peer.require_cap(STATUS_READ)?;
    let contact_id = crate::direct::connect::rotate_identity(&state)
        .await
        .map_err(map_anyhow)?;
    Ok(Json(DirectContactResponse { contact_id }))
}
