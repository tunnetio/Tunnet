//! Bootstrap / lifecycle operations invoked by the Local Management API.

use async_trait::async_trait;
use tunnet_common::local_api::{
    ApiError, AuthLoginRequest, CoreUpdateStatus, DeviceExpiryRequest, DeviceLabelDeleteRequest,
    DeviceLabelPatchRequest, DeviceLabelRequest, DeviceTagAddRequest, DeviceTagRemoveRequest,
    JsonPayload, LocalEnrollRequest, NetworkCreateRequest, NetworkJoinRequest, NetworkLeaveRequest,
    NetworkUpgradeRequest, OkResponse, PolicyOpRequest, PostureCheckRequest, ResetRequest,
    UpdateRequest, ValidateConfigRequest,
};

use super::handlers::{map_anyhow, result_ok};

/// Daemon-side bootstrap and lifecycle operations for `/v1/enroll`, `/v1/networks/*`, etc.
#[async_trait]
pub trait BootstrapOps: Send + Sync {
    async fn enroll(&self, req: LocalEnrollRequest) -> Result<OkResponse, ApiError>;
    async fn network_create(&self, req: NetworkCreateRequest) -> Result<OkResponse, ApiError>;
    async fn network_join(&self, req: NetworkJoinRequest) -> Result<OkResponse, ApiError>;
    async fn network_leave(&self, req: NetworkLeaveRequest) -> Result<OkResponse, ApiError>;
    async fn network_upgrade(&self, req: NetworkUpgradeRequest) -> Result<OkResponse, ApiError>;
    async fn reset(&self, req: ResetRequest) -> Result<OkResponse, ApiError>;
    async fn validate_config(&self, req: ValidateConfigRequest) -> Result<OkResponse, ApiError>;
    async fn auth_login(&self, req: AuthLoginRequest) -> Result<OkResponse, ApiError>;
    async fn auth_logout(&self) -> Result<OkResponse, ApiError>;
    async fn update_check(&self) -> Result<CoreUpdateStatus, ApiError>;
    async fn update(&self, req: UpdateRequest) -> Result<CoreUpdateStatus, ApiError>;
    async fn device_set_labels(&self, req: DeviceLabelRequest) -> Result<OkResponse, ApiError>;
    async fn device_patch_labels(
        &self,
        req: DeviceLabelPatchRequest,
    ) -> Result<OkResponse, ApiError>;
    async fn device_delete_label(
        &self,
        req: DeviceLabelDeleteRequest,
    ) -> Result<OkResponse, ApiError>;
    async fn device_add_tag(&self, req: DeviceTagAddRequest) -> Result<OkResponse, ApiError>;
    async fn device_remove_tag(&self, req: DeviceTagRemoveRequest) -> Result<OkResponse, ApiError>;
    async fn device_set_expiry(&self, req: DeviceExpiryRequest) -> Result<OkResponse, ApiError>;
    async fn posture_status(&self) -> Result<JsonPayload, ApiError>;
    async fn posture_check(&self, req: PostureCheckRequest) -> Result<JsonPayload, ApiError>;
    async fn policy_op(&self, req: PolicyOpRequest) -> Result<JsonPayload, ApiError>;
    async fn device_info(&self) -> Result<JsonPayload, ApiError>;

    /// Idle Local API node GET uses the runtime snapshot when a handle exists.
    fn observe_mesh(&self) -> Option<super::observe::MeshObservation> {
        None
    }
}

/// Map an `anyhow` error into a structured [`ApiError`].
pub fn map_error(e: impl std::fmt::Display) -> ApiError {
    map_anyhow(e)
}

pub fn ok(message: impl Into<String>) -> OkResponse {
    result_ok(message)
}
