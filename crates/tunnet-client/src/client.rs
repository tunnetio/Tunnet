//! Typed HTTP client for the Tunnet Local Management API (`/v1/...`).

use std::path::Path;

use anyhow::{Context, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tunnet_common::local_api::{
    ApiError, ApiErrorCode, AuthLoginRequest, CoreUpdateStatus, DataPlaneStatus,
    DeviceExpiryRequest, DeviceLabelDeleteRequest, DeviceLabelPatchRequest, DeviceLabelRequest,
    DeviceTagAddRequest, DeviceTagRemoveRequest, DiagInfo, DirectConnectContactRequest,
    DirectConnectPendingResponse, DirectConnectRequest, DirectContactResponse,
    DirectFirewallAddRequest, DirectFirewallPendingResponse, DirectFirewallResponse,
    DirectInviteRequest, DirectInviteResponse, DirectKeepAliveRequest, DirectNetworkRequest,
    DirectPendingResponse, DirectPolicyResponse, DirectPolicySetRequest, DnsStatusInfo,
    JsonPayload, LocalEnrollRequest, LocalEvent, MetaInfo, NetcheckInfo, NetworkCreateRequest,
    NetworkJoinRequest, NetworkLeaveRequest, NetworkSummary, NetworkUpgradeRequest,
    NetworksResponse, NodeSummary, OkResponse, PeersResponse, PingEvent, PolicyOpRequest,
    PostureCheckRequest, ResetRequest, RouteAddRequest, RouteAddedResponse, RoutesInfo,
    SendAcceptRequest, SendConfigInfo, SendFileRequest, SendRejectRequest, SendSetConfigRequest,
    ServeInfo, ServeStartRequest, ServesResponse, SshAuthPollRequest, SshAuthPollResponse,
    SshCastResponse, SshRecordingsResponse, SshSessionsResponse, TransferInfo, TransfersResponse,
    TunnelInfo, TunnelStartRequest, TunnelsResponse, UpdateRequest, ValidateConfigRequest,
    format_api_error,
};

use crate::transport::{self, default_api_path};

#[derive(Serialize)]
struct EmptyBody {}

/// HTTP client for the Local Management API (Unix socket / named pipe).
#[derive(Clone, Debug)]
pub struct TunnetClient {
    path: std::path::PathBuf,
}

/// Back-compat alias for [`TunnetClient`].
pub type LocalApiClient = TunnetClient;

impl TunnetClient {
    pub fn connect() -> Self {
        Self {
            path: default_api_path(),
        }
    }

    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // -----------------------------------------------------------------------
    // Status / networking
    // -----------------------------------------------------------------------

    pub async fn meta(&self) -> anyhow::Result<MetaInfo> {
        self.get_json("/v1/meta").await
    }

    pub async fn node(&self) -> anyhow::Result<NodeSummary> {
        self.get_json("/v1/node").await
    }

    pub async fn networks(&self) -> anyhow::Result<NetworksResponse> {
        self.get_json("/v1/networks").await
    }

    pub async fn network(&self, network_id: &str) -> anyhow::Result<NetworkSummary> {
        self.get_json(&format!("/v1/networks/{}", urlencoding(network_id)))
            .await
    }

    pub async fn network_peers(&self, network_id: &str) -> anyhow::Result<PeersResponse> {
        self.get_json(&format!("/v1/networks/{}/peers", urlencoding(network_id)))
            .await
    }

    pub async fn network_routes(&self, network_id: &str) -> anyhow::Result<RoutesInfo> {
        self.get_json(&format!("/v1/networks/{}/routes", urlencoding(network_id)))
            .await
    }

    pub async fn network_firewall(
        &self,
        network_id: &str,
    ) -> anyhow::Result<DirectFirewallResponse> {
        self.get_json(&format!(
            "/v1/networks/{}/firewall",
            urlencoding(network_id)
        ))
        .await
    }

    pub async fn network_join_requests(
        &self,
        network_id: &str,
    ) -> anyhow::Result<DirectPendingResponse> {
        self.get_json(&format!(
            "/v1/networks/{}/join-requests",
            urlencoding(network_id)
        ))
        .await
    }

    pub async fn network_join_accept(
        &self,
        network_id: &str,
        peer_id: &str,
    ) -> anyhow::Result<OkResponse> {
        self.post_json(
            &format!(
                "/v1/networks/{}/join-requests/{}/accept",
                urlencoding(network_id),
                urlencoding(peer_id)
            ),
            &EmptyBody {},
        )
        .await
    }

    pub async fn network_join_deny(
        &self,
        network_id: &str,
        peer_id: &str,
    ) -> anyhow::Result<OkResponse> {
        self.post_json(
            &format!(
                "/v1/networks/{}/join-requests/{}/deny",
                urlencoding(network_id),
                urlencoding(peer_id)
            ),
            &EmptyBody {},
        )
        .await
    }

    /// Stream local daemon events from `GET /v1/events` (SSE).
    pub async fn events<F>(&self, mut on_event: F) -> anyhow::Result<()>
    where
        F: FnMut(LocalEvent) -> anyhow::Result<()>,
    {
        let (status, bytes) = self
            .raw_request("GET", "/v1/events", None::<&EmptyBody>)
            .await?;
        if !(200..300).contains(&status) {
            if let Ok(err) = serde_json::from_slice::<ApiError>(&bytes) {
                bail!("{}", format_api_error(&err.code, &err.message));
            }
            bail!("events SSE failed ({status})");
        }

        parse_events_sse(&bytes, &mut on_event)
    }

    pub async fn dns(&self) -> anyhow::Result<DnsStatusInfo> {
        self.get_json("/v1/dns").await
    }

    pub async fn routes_list(&self, network_id: Option<&str>) -> anyhow::Result<RoutesInfo> {
        let uri = match network_id {
            Some(id) => format!("/v1/routes?network_id={}", urlencoding(id)),
            None => "/v1/routes".to_string(),
        };
        self.get_json(&uri).await
    }

    pub async fn routes_add(
        &self,
        cidr: impl Into<String>,
        description: Option<String>,
    ) -> anyhow::Result<RouteAddedResponse> {
        let body = RouteAddRequest {
            cidr: cidr.into(),
            description,
        };
        self.post_json("/v1/routes", &body).await
    }

    /// Stream ping probes and a final summary from `GET /v1/ping/{peer}` (SSE).
    pub async fn ping<F>(
        &self,
        peer: &str,
        count: u32,
        interval_ms: u64,
        mut on_event: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(PingEvent) -> anyhow::Result<()>,
    {
        let uri = format!(
            "/v1/ping/{}?count={count}&interval_ms={interval_ms}",
            urlencoding(peer)
        );
        let (status, bytes) = self.raw_request("GET", &uri, None::<&EmptyBody>).await?;
        if !(200..300).contains(&status) {
            if let Ok(err) = serde_json::from_slice::<ApiError>(&bytes) {
                bail!("{}", format_api_error(&err.code, &err.message));
            }
            bail!("ping SSE failed ({status})");
        }

        parse_ping_sse(&bytes, &mut on_event)
    }

    pub async fn diag(&self) -> anyhow::Result<DiagInfo> {
        self.get_json("/v1/diag").await
    }

    pub async fn netcheck(&self) -> anyhow::Result<NetcheckInfo> {
        self.get_json("/v1/netcheck").await
    }

    pub async fn reload(&self) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/reload", &EmptyBody {}).await
    }

    // -----------------------------------------------------------------------
    // Data plane
    // -----------------------------------------------------------------------

    pub async fn data_plane_status(&self) -> anyhow::Result<DataPlaneStatus> {
        self.get_json("/v1/data-plane").await
    }

    pub async fn data_plane_up(&self) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/data-plane/up", &EmptyBody {}).await
    }

    pub async fn data_plane_down(&self) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/data-plane/down", &EmptyBody {}).await
    }

    // -----------------------------------------------------------------------
    // Serve / tunnel
    // -----------------------------------------------------------------------

    pub async fn serves_list(&self) -> anyhow::Result<ServesResponse> {
        self.get_json("/v1/serves").await
    }

    pub async fn serves_start(&self, body: &ServeStartRequest) -> anyhow::Result<ServeInfo> {
        self.post_json("/v1/serves", body).await
    }

    pub async fn serves_off(&self, port: u16) -> anyhow::Result<ServeInfo> {
        self.delete_json(&format!("/v1/serves/{port}")).await
    }

    pub async fn tunnels_list(&self) -> anyhow::Result<TunnelsResponse> {
        self.get_json("/v1/tunnels").await
    }

    pub async fn tunnels_start(&self, body: &TunnelStartRequest) -> anyhow::Result<TunnelInfo> {
        self.post_json("/v1/tunnels", body).await
    }

    pub async fn tunnels_off(&self, port: u16) -> anyhow::Result<TunnelInfo> {
        self.delete_json(&format!("/v1/tunnels/{port}")).await
    }

    // -----------------------------------------------------------------------
    // SSH
    // -----------------------------------------------------------------------

    pub async fn ssh_sessions(
        &self,
        limit: u32,
        status: Option<&str>,
    ) -> anyhow::Result<SshSessionsResponse> {
        let mut uri = format!("/v1/ssh/sessions?limit={limit}");
        if let Some(s) = status {
            uri.push_str(&format!("&status={}", urlencoding(s)));
        }
        self.get_json(&uri).await
    }

    pub async fn ssh_recordings(&self, limit: u32) -> anyhow::Result<SshRecordingsResponse> {
        self.get_json(&format!("/v1/ssh/recordings?limit={limit}"))
            .await
    }

    pub async fn ssh_cast(&self, session_id: &str) -> anyhow::Result<SshCastResponse> {
        self.get_json(&format!(
            "/v1/ssh/recordings/{}/cast",
            urlencoding(session_id)
        ))
        .await
    }

    pub async fn ssh_auth_poll(
        &self,
        challenge_token: impl Into<String>,
    ) -> anyhow::Result<SshAuthPollResponse> {
        let body = SshAuthPollRequest {
            challenge_token: challenge_token.into(),
        };
        self.post_json("/v1/ssh/auth/poll", &body).await
    }

    // -----------------------------------------------------------------------
    // File transfer (send)
    // -----------------------------------------------------------------------

    pub async fn transfers_send(
        &self,
        body: &SendFileRequest,
    ) -> anyhow::Result<TransfersResponse> {
        self.post_json("/v1/transfers/send", body).await
    }

    pub async fn transfers_list(&self) -> anyhow::Result<TransfersResponse> {
        self.get_json("/v1/transfers").await
    }

    pub async fn transfers_history(&self) -> anyhow::Result<TransfersResponse> {
        self.get_json("/v1/transfers/history").await
    }

    pub async fn transfers_accept(&self, transfer_id: &str) -> anyhow::Result<TransferInfo> {
        let body = SendAcceptRequest {
            transfer_id: transfer_id.to_string(),
        };
        self.post_json(
            &format!("/v1/transfers/{}/accept", urlencoding(transfer_id)),
            &body,
        )
        .await
    }

    pub async fn transfers_reject(
        &self,
        transfer_id: &str,
        reason: Option<String>,
    ) -> anyhow::Result<OkResponse> {
        let body = SendRejectRequest {
            transfer_id: transfer_id.to_string(),
            reason,
        };
        self.post_json(
            &format!("/v1/transfers/{}/reject", urlencoding(transfer_id)),
            &body,
        )
        .await
    }

    pub async fn send_config(&self) -> anyhow::Result<SendConfigInfo> {
        self.get_json("/v1/send/config").await
    }

    pub async fn send_set_config(
        &self,
        body: &SendSetConfigRequest,
    ) -> anyhow::Result<SendConfigInfo> {
        self.put_json("/v1/send/config", body).await
    }

    // -----------------------------------------------------------------------
    // Direct mode
    // -----------------------------------------------------------------------

    pub async fn direct_invite(
        &self,
        body: &DirectInviteRequest,
    ) -> anyhow::Result<DirectInviteResponse> {
        self.post_json("/v1/direct/invites", body).await
    }

    pub async fn direct_requests(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<DirectPendingResponse> {
        self.get_json(&network_query("/v1/direct/requests", network))
            .await
    }

    pub async fn direct_accept(
        &self,
        peer_id: &str,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let uri = network_query(
            &format!("/v1/direct/requests/{}/accept", urlencoding(peer_id)),
            network,
        );
        self.post_json(&uri, &EmptyBody {}).await
    }

    pub async fn direct_deny(
        &self,
        peer_id: &str,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let uri = network_query(
            &format!("/v1/direct/requests/{}/deny", urlencoding(peer_id)),
            network,
        );
        self.post_json(&uri, &EmptyBody {}).await
    }

    pub async fn direct_kick(
        &self,
        peer_id: &str,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let uri = network_query(
            &format!("/v1/direct/peers/{}/kick", urlencoding(peer_id)),
            network,
        );
        self.post_json(&uri, &EmptyBody {}).await
    }

    pub async fn direct_firewall_show(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<DirectFirewallResponse> {
        self.get_json(&network_query("/v1/direct/firewall", network))
            .await
    }

    pub async fn direct_firewall_off(&self, network: Option<&str>) -> anyhow::Result<OkResponse> {
        let body = DirectNetworkRequest {
            network: network.map(str::to_string),
        };
        self.post_json("/v1/direct/firewall/off", &body).await
    }

    pub async fn direct_firewall_add(
        &self,
        body: &DirectFirewallAddRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/direct/firewall/rules", body).await
    }

    pub async fn direct_firewall_remove(
        &self,
        index: usize,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let uri = network_query(&format!("/v1/direct/firewall/rules/{index}"), network);
        self.delete_json(&uri).await
    }

    pub async fn direct_firewall_reset(&self, network: Option<&str>) -> anyhow::Result<OkResponse> {
        let body = DirectNetworkRequest {
            network: network.map(str::to_string),
        };
        self.post_json("/v1/direct/firewall/reset", &body).await
    }

    pub async fn direct_firewall_flush_conntrack(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let body = DirectNetworkRequest {
            network: network.map(str::to_string),
        };
        self.post_json("/v1/direct/firewall/conntrack/flush", &body)
            .await
    }

    pub async fn direct_firewall_pending(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<DirectFirewallPendingResponse> {
        self.get_json(&network_query("/v1/direct/firewall/pending", network))
            .await
    }

    pub async fn direct_firewall_accept_suggestion(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let body = DirectNetworkRequest {
            network: network.map(str::to_string),
        };
        self.post_json("/v1/direct/firewall/pending/accept", &body)
            .await
    }

    pub async fn direct_firewall_reject_suggestion(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<OkResponse> {
        let body = DirectNetworkRequest {
            network: network.map(str::to_string),
        };
        self.post_json("/v1/direct/firewall/pending/reject", &body)
            .await
    }

    pub async fn direct_policy_show(
        &self,
        network: Option<&str>,
    ) -> anyhow::Result<DirectPolicyResponse> {
        self.get_json(&network_query("/v1/direct/policy", network))
            .await
    }

    pub async fn direct_policy_set(
        &self,
        body: &DirectPolicySetRequest,
    ) -> anyhow::Result<OkResponse> {
        self.put_json("/v1/direct/policy", body).await
    }

    pub async fn direct_policy_clear(&self, network: Option<&str>) -> anyhow::Result<OkResponse> {
        self.delete_json(&network_query("/v1/direct/policy", network))
            .await
    }

    pub async fn direct_keep_alive(
        &self,
        body: &DirectKeepAliveRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/direct/keep-alive", body).await
    }

    pub async fn direct_connect(
        &self,
        contact_id: impl Into<String>,
    ) -> anyhow::Result<OkResponse> {
        let body = DirectConnectRequest {
            contact_id: contact_id.into(),
        };
        self.post_json("/v1/direct/connect", &body).await
    }

    pub async fn direct_connect_allow(
        &self,
        contact_id: impl Into<String>,
    ) -> anyhow::Result<OkResponse> {
        let body = DirectConnectContactRequest {
            contact_id: contact_id.into(),
        };
        self.post_json("/v1/direct/connect/allow", &body).await
    }

    pub async fn direct_connect_pending(&self) -> anyhow::Result<DirectConnectPendingResponse> {
        self.get_json("/v1/direct/connect/pending").await
    }

    pub async fn direct_connect_accept(&self, contact_id: &str) -> anyhow::Result<OkResponse> {
        self.post_json(
            &format!(
                "/v1/direct/connect/pending/{}/accept",
                urlencoding(contact_id)
            ),
            &EmptyBody {},
        )
        .await
    }

    pub async fn direct_connect_deny(&self, contact_id: &str) -> anyhow::Result<OkResponse> {
        self.post_json(
            &format!(
                "/v1/direct/connect/pending/{}/deny",
                urlencoding(contact_id)
            ),
            &EmptyBody {},
        )
        .await
    }

    pub async fn direct_connect_rotate(&self) -> anyhow::Result<DirectContactResponse> {
        self.post_json("/v1/direct/connect/rotate", &EmptyBody {})
            .await
    }

    // -----------------------------------------------------------------------
    // Bootstrap / lifecycle (phase-2 stubs on server)
    // -----------------------------------------------------------------------

    pub async fn enroll(&self, body: &LocalEnrollRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/enroll", body).await
    }

    pub async fn network_create(&self, body: &NetworkCreateRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/networks", body).await
    }

    pub async fn network_join(&self, body: &NetworkJoinRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/networks/join", body).await
    }

    pub async fn network_leave(&self, body: &NetworkLeaveRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/networks/leave", body).await
    }

    pub async fn network_upgrade(
        &self,
        body: &NetworkUpgradeRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/networks/upgrade", body).await
    }

    pub async fn reset(&self, body: &ResetRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/reset", body).await
    }

    pub async fn validate_config(
        &self,
        body: &ValidateConfigRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/config/validate", body).await
    }

    pub async fn auth_login(&self, body: &AuthLoginRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/auth/login", body).await
    }

    pub async fn auth_logout(&self) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/auth/logout", &EmptyBody {}).await
    }

    pub async fn update(&self, body: &UpdateRequest) -> anyhow::Result<CoreUpdateStatus> {
        self.post_json("/v1/update", body).await
    }

    pub async fn update_check(&self) -> anyhow::Result<CoreUpdateStatus> {
        self.get_json("/v1/update").await
    }

    pub async fn update_status(&self) -> anyhow::Result<CoreUpdateStatus> {
        self.update_check().await
    }

    // -----------------------------------------------------------------------
    // Device metadata
    // -----------------------------------------------------------------------

    pub async fn device_labels_set(&self, body: &DeviceLabelRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/labels", body).await
    }

    pub async fn device_labels_patch(
        &self,
        body: &DeviceLabelPatchRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/labels/patch", body).await
    }

    pub async fn device_labels_delete(
        &self,
        body: &DeviceLabelDeleteRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/labels/delete", body).await
    }

    pub async fn device_tags_add(&self, body: &DeviceTagAddRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/tags", body).await
    }

    pub async fn device_tags_remove(
        &self,
        body: &DeviceTagRemoveRequest,
    ) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/tags/remove", body).await
    }

    pub async fn device_expiry(&self, body: &DeviceExpiryRequest) -> anyhow::Result<OkResponse> {
        self.post_json("/v1/device/expiry", body).await
    }

    pub async fn posture_status(&self) -> anyhow::Result<JsonPayload> {
        self.get_json("/v1/posture").await
    }

    pub async fn posture_check(&self, body: &PostureCheckRequest) -> anyhow::Result<JsonPayload> {
        self.post_json("/v1/posture/check", body).await
    }

    pub async fn policy_op(&self, body: &PolicyOpRequest) -> anyhow::Result<JsonPayload> {
        self.post_json("/v1/policy", body).await
    }

    pub async fn device_info(&self) -> anyhow::Result<JsonPayload> {
        self.get_json("/v1/device").await
    }

    // -----------------------------------------------------------------------
    // Low-level HTTP
    // -----------------------------------------------------------------------

    pub async fn get_json<T: DeserializeOwned>(&self, uri: &str) -> anyhow::Result<T> {
        self.request_json("GET", uri, None::<()>).await
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        uri: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        self.request_json("POST", uri, Some(body)).await
    }

    pub async fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        uri: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        self.request_json("PUT", uri, Some(body)).await
    }

    pub async fn delete_json<T: DeserializeOwned>(&self, uri: &str) -> anyhow::Result<T> {
        self.request_json("DELETE", uri, None::<()>).await
    }

    async fn request_json<B: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        uri: &str,
        body: Option<B>,
    ) -> anyhow::Result<T> {
        let (status, bytes) = self.raw_request(method, uri, body.as_ref()).await?;
        if !(200..300).contains(&status) {
            if let Ok(err) = serde_json::from_slice::<ApiError>(&bytes) {
                bail!("{}", format_api_error(&err.code, &err.message));
            }
            bail!(
                "Local API {method} {uri} failed ({status}): {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "decode Local API response for {method} {uri}: {}",
                String::from_utf8_lossy(&bytes)
            )
        })
    }

    async fn raw_request<B: Serialize>(
        &self,
        method: &str,
        uri: &str,
        body: Option<&B>,
    ) -> anyhow::Result<(u16, Bytes)> {
        let stream = transport::connect(&self.path)
            .await
            .map_err(|_| anyhow::anyhow!(format_api_error(&ApiErrorCode::DaemonNotRunning, "")))?;

        let io = match stream {
            #[cfg(unix)]
            transport::ClientStream::Unix(s) => TokioIo::new(s),
            #[cfg(windows)]
            transport::ClientStream::Windows(s) => TokioIo::new(s),
        };

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake with Local API")?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(?e, "Local API client connection closed");
            }
        });

        let mut builder = Request::builder().method(method).uri(uri);
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            let bytes = serde_json::to_vec(b)?;
            builder.body(Full::new(Bytes::from(bytes)))?
        } else {
            builder.body(Full::new(Bytes::new()))?
        };

        let res = sender
            .send_request(req)
            .await
            .context("send Local API request")?;
        let status = res.status().as_u16();
        let collected = res
            .into_body()
            .collect()
            .await
            .context("read Local API body")?;
        Ok((status, collected.to_bytes()))
    }
}

fn network_query(base: &str, network: Option<&str>) -> String {
    match network {
        Some(n) => format!("{base}?network={}", urlencoding(n)),
        None => base.to_string(),
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_sse_data<F, T>(
    bytes: &Bytes,
    mut on_event: F,
    stop_on: impl Fn(&T) -> bool,
) -> anyhow::Result<()>
where
    F: FnMut(T) -> anyhow::Result<()>,
    T: serde::de::DeserializeOwned,
{
    let text = String::from_utf8_lossy(bytes);
    for block in text.split("\n\n") {
        for line in block.lines() {
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<T>(data) {
                let done = stop_on(&event);
                on_event(event)?;
                if done {
                    return Ok(());
                }
            } else if let Ok(err) = serde_json::from_str::<ApiError>(data) {
                bail!("{}", format_api_error(&err.code, &err.message));
            }
        }
    }
    Ok(())
}

fn parse_ping_sse<F>(bytes: &Bytes, on_event: &mut F) -> anyhow::Result<()>
where
    F: FnMut(PingEvent) -> anyhow::Result<()>,
{
    parse_sse_data(bytes, on_event, |event| {
        matches!(event, PingEvent::Summary(_))
    })
}

fn parse_events_sse<F>(bytes: &Bytes, on_event: &mut F) -> anyhow::Result<()>
where
    F: FnMut(LocalEvent) -> anyhow::Result<()>,
{
    parse_sse_data(bytes, on_event, |_| false)
}
