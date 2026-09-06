//! [`BootstrapOps`] implementation for the running agent daemon.

use std::collections::HashMap;

use async_trait::async_trait;
use tunnet_common::local_api::{
    ApiError, AuthLoginRequest, CoreUpdateStatus, DeviceExpiryRequest, DeviceLabelDeleteRequest,
    DeviceLabelPatchRequest, DeviceLabelRequest, DeviceTagAddRequest, DeviceTagRemoveRequest,
    JsonPayload, LocalEnrollRequest, NetworkCreateRequest, NetworkJoinRequest, NetworkLeaveRequest,
    NetworkUpgradeRequest, OkResponse, PolicyOpRequest, PostureCheckRequest, ResetRequest,
    UpdateRequest, ValidateConfigRequest,
};
use tunnet_core::local_api::bootstrap::{BootstrapOps, map_error, ok};
use tunnet_core::{SealPolicy, SignedClient, StatePaths, load_agent};
use tunnet_policy_engine::{
    Format, PolicyDocument, content_hash, export_hcl, export_json, export_terraform, export_yaml,
    fmt_json, parse_document, run_tests, simulate, validate,
};
use tunnet_posture::{
    PostureEngine, PostureEngineConfig, PostureScoringConfig, compute_posture_score,
    evaluate_named_postures, parse_assertion,
};

pub struct AgentBootstrapOps {
    paths: StatePaths,
    updater: std::sync::Arc<crate::core_update::CoreUpdater>,
}

impl AgentBootstrapOps {
    pub fn new(
        paths: StatePaths,
        events: tokio::sync::broadcast::Sender<tunnet_common::local_api::LocalEvent>,
    ) -> Self {
        let updater = crate::core_update::CoreUpdater::shared(paths.clone(), events);
        Self { paths, updater }
    }

    fn state_dir(&self) -> Option<String> {
        Some(self.paths.dir.to_string_lossy().into_owned())
    }

    async fn signed_client(&self) -> anyhow::Result<SignedClient> {
        let policy = SealPolicy::from_env_and_flag(false);
        let (identity, persisted, _) = load_agent(&self.paths, policy)?;
        let managed = match persisted {
            tunnet_core::PersistedState::Managed(m) => m,
            _ => anyhow::bail!("not enrolled in Managed mode"),
        };
        SignedClient::new(
            managed.control_url.clone(),
            identity.endpoint_id_hex(),
            identity.signing_key.clone(),
        )
    }
}

fn normalize_tag(raw: &str) -> String {
    raw.trim().trim_start_matches("tag:").to_lowercase()
}

fn local_posture_engine() -> PostureEngine {
    let config = PostureEngineConfig {
        tunnet_version: env!("CARGO_PKG_VERSION").to_string(),
        ..PostureEngineConfig::default()
    };
    PostureEngine::with_default_collectors(config)
}

fn json_payload(data: serde_json::Value) -> JsonPayload {
    JsonPayload { data }
}

fn policy_format_str(format: Format) -> &'static str {
    match format {
        Format::Json => "json",
        Format::Hcl => "hcl",
        Format::Yaml => "yaml",
    }
}

fn policy_documents_payload(req: &PolicyOpRequest) -> Result<Vec<serde_json::Value>, ApiError> {
    let content = req
        .path_contents
        .as_ref()
        .ok_or_else(|| map_error("path_contents required"))?;
    let path_name = req.path_name.as_deref().unwrap_or("policy.json");
    let format = Format::from_path(path_name)
        .ok_or_else(|| map_error("unsupported file extension; use .json, .hcl, or .yaml"))?;
    Ok(vec![serde_json::json!({
        "path": path_name,
        "format": policy_format_str(format),
        "content": content,
    })])
}

fn load_policy_document(req: &PolicyOpRequest) -> Result<PolicyDocument, ApiError> {
    let content = req
        .path_contents
        .as_ref()
        .ok_or_else(|| map_error("path_contents required"))?;
    let path_name = req.path_name.as_deref().unwrap_or("policy.json");
    let format = Format::from_path(path_name)
        .ok_or_else(|| map_error("unsupported file extension; use .json, .hcl, or .yaml"))?;
    parse_document(format, content).map_err(map_error)
}

#[async_trait]
impl BootstrapOps for AgentBootstrapOps {
    async fn enroll(&self, req: LocalEnrollRequest) -> Result<OkResponse, ApiError> {
        let labels_json = req
            .labels
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(map_error)?;
        let args = crate::cli::EnrollArgs {
            control_url: req.control_url,
            token: req.token,
            org: req.org,
            network: req.network,
            hostname: req.hostname,
            wait_secs: req.wait_secs,
            labels: None,
            labels_json,
            expires_in: req.expires_in,
            no_encrypt_state: req.no_encrypt_state,
            management_url: req.management_url,
            dashboard_url: req.dashboard_url,
        };
        crate::cli::run_enroll(args, self.state_dir().as_deref())
            .await
            .map_err(|e| map_error(format!("{e:#}")))?;
        Ok(ok("enrolled"))
    }

    async fn network_create(&self, req: NetworkCreateRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_direct::CreateArgs {
            hostname: req.hostname,
            open: req.open,
            network_name: req.network_name,
            secret: req.secret,
            cidr: req.cidr,
            no_encrypt_state: req.no_encrypt_state,
        };
        crate::cmds_direct::run_create(args, self.state_dir().as_deref())
            .await
            .map_err(map_error)?;
        Ok(ok("direct network created"))
    }

    async fn network_join(&self, req: NetworkJoinRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_direct::JoinArgs {
            invite_code: req.invite_code,
            hostname: req.hostname,
            auto_accept_firewall: req.auto_accept_firewall,
            no_encrypt_state: req.no_encrypt_state,
        };
        crate::cmds_direct::run_join(args, self.state_dir().as_deref())
            .await
            .map_err(map_error)?;
        Ok(ok("joined direct network"))
    }

    async fn network_leave(&self, req: NetworkLeaveRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_direct::LeaveArgs {
            network: req.network,
            name: req.name,
        };
        crate::cmds_direct::run_leave(args, self.state_dir().as_deref())
            .await
            .map_err(map_error)?;
        Ok(ok("left direct network"))
    }

    async fn network_upgrade(&self, req: NetworkUpgradeRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_direct::UpgradeArgs {
            control_url: req.control_url,
            token: req.token,
        };
        crate::cmds_direct::run_upgrade(args, self.state_dir().as_deref())
            .await
            .map_err(map_error)?;
        Ok(ok("upgraded to managed network"))
    }

    async fn reset(&self, req: ResetRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cli::ResetArgs { yes: req.yes };
        crate::cli::run_reset(args, self.state_dir().as_deref())
            .await
            .map_err(map_error)?;
        Ok(ok(if req.yes {
            "state wiped"
        } else {
            "confirmation required; set yes=true to wipe"
        }))
    }

    async fn validate_config(&self, req: ValidateConfigRequest) -> Result<OkResponse, ApiError> {
        use std::path::Path;
        use tunnet_core::TunnetConfig;

        let cfg = if let Some(contents) = &req.contents {
            tunnet_core::agent_config::parse_toml(contents)
                .map_err(|e| map_error(format!("parse config: {e}")))?
        } else if let Some(path) = &req.path {
            TunnetConfig::load_path(Path::new(path)).map_err(map_error)?
        } else {
            TunnetConfig::ensure(&self.paths).map_err(map_error)?
        };

        match cfg.validate() {
            Ok(()) => Ok(ok("tunnet.toml: ok")),
            Err(errs) => Err(map_error(format!(
                "{} validation error(s): {}",
                errs.len(),
                errs.join("; ")
            ))),
        }
    }

    async fn auth_login(&self, req: AuthLoginRequest) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_login::LoginArgs {
            management_url: req.management_url,
            state_dir: self.state_dir(),
        };
        crate::cmds_login::run_login(args)
            .await
            .map_err(map_error)?;
        Ok(ok("logged in"))
    }

    async fn auth_logout(&self) -> Result<OkResponse, ApiError> {
        let args = crate::cmds_login::LogoutArgs {
            state_dir: self.state_dir(),
        };
        crate::cmds_login::run_logout(args)
            .await
            .map_err(map_error)?;
        Ok(ok("logged out"))
    }

    async fn update_check(&self) -> Result<CoreUpdateStatus, ApiError> {
        self.updater.check().await.map_err(map_error)
    }

    async fn update(&self, req: UpdateRequest) -> Result<CoreUpdateStatus, ApiError> {
        if req.version.is_some() {
            return Err(map_error(
                "specific Core versions are not accepted by the stable update channel",
            ));
        }
        self.updater
            .stage_and_activate(req.force)
            .await
            .map_err(map_error)
    }

    async fn device_set_labels(&self, req: DeviceLabelRequest) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        let patch = req
            .labels
            .into_iter()
            .map(|(k, v)| (k, Some(v)))
            .collect::<HashMap<_, _>>();
        client
            .patch_device_labels(&patch)
            .await
            .map_err(map_error)?;
        Ok(ok("labels updated"))
    }

    async fn device_patch_labels(
        &self,
        req: DeviceLabelPatchRequest,
    ) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        client
            .patch_device_labels(&req.labels)
            .await
            .map_err(map_error)?;
        Ok(ok("labels patched"))
    }

    async fn device_delete_label(
        &self,
        req: DeviceLabelDeleteRequest,
    ) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        let mut patch = HashMap::new();
        patch.insert(req.key, None);
        client
            .patch_device_labels(&patch)
            .await
            .map_err(map_error)?;
        Ok(ok("label deleted"))
    }

    async fn device_add_tag(&self, req: DeviceTagAddRequest) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        let tag = normalize_tag(&req.tag);
        client
            .patch_device_tags(&[tag], &[])
            .await
            .map_err(map_error)?;
        Ok(ok("tag added"))
    }

    async fn device_remove_tag(&self, req: DeviceTagRemoveRequest) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        let tag = normalize_tag(&req.tag);
        client
            .patch_device_tags(&[], &[tag])
            .await
            .map_err(map_error)?;
        Ok(ok("tag removed"))
    }

    async fn device_set_expiry(&self, req: DeviceExpiryRequest) -> Result<OkResponse, ApiError> {
        let client = self.signed_client().await.map_err(map_error)?;
        let duration = req.duration.trim();
        let value = if duration.eq_ignore_ascii_case("never") {
            None
        } else {
            Some(duration)
        };
        client.patch_device_expiry(value).await.map_err(map_error)?;
        Ok(ok(match value {
            Some(d) => format!("expiry set to {d}"),
            None => "auto-expiry disabled".into(),
        }))
    }

    async fn posture_status(&self) -> Result<JsonPayload, ApiError> {
        let engine = local_posture_engine();
        engine
            .collect_once()
            .await
            .map_err(|e| map_error(format!("collect posture: {e}")))?;
        let attrs = engine.state().await.attributes;
        let rows: Vec<_> = attrs
            .iter()
            .map(|(k, v)| serde_json::json!({ "attribute": k, "value": v }))
            .collect();
        Ok(json_payload(serde_json::json!({ "attributes": rows })))
    }

    async fn posture_check(&self, req: PostureCheckRequest) -> Result<JsonPayload, ApiError> {
        let engine = local_posture_engine();
        engine
            .collect_once()
            .await
            .map_err(|e| map_error(format!("collect posture: {e}")))?;
        let attrs = engine.state().await.attributes;

        let raw_definitions = if let Some(raw) = &req.definitions_json {
            serde_json::from_str::<HashMap<String, Vec<String>>>(raw)
                .map_err(|e| map_error(format!("parse posture definitions JSON: {e}")))?
        } else {
            HashMap::new()
        };

        let definitions: HashMap<String, Vec<_>> = raw_definitions
            .into_iter()
            .map(|(name, lines)| {
                let assertions = lines
                    .iter()
                    .filter_map(|l| parse_assertion(l).ok())
                    .collect();
                (name, assertions)
            })
            .collect();

        let names: Vec<String> = definitions.keys().cloned().collect();
        let summary = if definitions.is_empty() {
            tunnet_posture::PostureEvalSummary {
                passed: true,
                results: HashMap::new(),
            }
        } else {
            evaluate_named_postures(&definitions, &names, &attrs)
        };

        let score = compute_posture_score(&attrs, &PostureScoringConfig::default_weights());

        Ok(json_payload(serde_json::json!({
            "score": score,
            "passed": summary.passed,
            "results": summary.results.iter().map(|(name, r)| serde_json::json!({
                "name": name,
                "passed": r.passed,
                "failing_assertions": r.failing_assertions,
            })).collect::<Vec<_>>(),
            "attributes": attrs,
        })))
    }

    async fn policy_op(&self, req: PolicyOpRequest) -> Result<JsonPayload, ApiError> {
        match req.op.as_str() {
            "validate" => {
                let doc = load_policy_document(&req)?;
                let result = validate(&doc);
                Ok(json_payload(serde_json::json!({
                    "valid": result.valid,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "hash": if result.valid { Some(content_hash(&doc)) } else { None },
                })))
            }
            "test" => {
                let doc = load_policy_document(&req)?;
                let results = run_tests(&doc);
                Ok(json_payload(serde_json::json!({
                    "passed": results.passed,
                    "failed": results.failed,
                    "results": results.results,
                })))
            }
            "simulate" => {
                let doc = load_policy_document(&req)?;
                let src = req
                    .from
                    .as_deref()
                    .ok_or_else(|| map_error("from is required for simulate"))?;
                let dst = req
                    .to
                    .as_deref()
                    .ok_or_else(|| map_error("to is required for simulate"))?;
                let result = simulate(&doc, src, dst, None, "tcp");
                Ok(json_payload(serde_json::json!({
                    "src": src,
                    "dst": dst,
                    "verdict": result.verdict,
                    "matched_rules": result.matched_rules,
                })))
            }
            "fmt" => {
                let doc = load_policy_document(&req)?;
                let formatted = fmt_json(&doc);
                Ok(json_payload(serde_json::json!({ "content": formatted })))
            }
            "export" => {
                if req.path_contents.is_none() {
                    let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                    let format = req.format.as_deref().unwrap_or("json");
                    let (status, value) = api
                        .get_json(&format!("/policy/export?format={format}"))
                        .await
                        .map_err(map_error)?;
                    crate::policy_api::require_ok(status, &value, "policy export")
                        .map_err(map_error)?;
                    return Ok(json_payload(value));
                }
                let doc = load_policy_document(&req)?;
                let format = req.format.as_deref().unwrap_or("json");
                let rendered = match format {
                    "hcl" => export_hcl(&doc),
                    "yaml" => export_yaml(&doc),
                    "terraform" => export_terraform(&doc),
                    _ => export_json(&doc),
                };
                Ok(json_payload(
                    serde_json::json!({ "content": rendered, "format": format }),
                ))
            }
            "diff" => {
                let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                let body = serde_json::json!({ "documents": policy_documents_payload(&req)? });
                let (status, value) = api
                    .post_json("/policy/diff", &body)
                    .await
                    .map_err(map_error)?;
                crate::policy_api::require_ok(status, &value, "policy diff").map_err(map_error)?;
                Ok(json_payload(value))
            }
            "apply" => {
                let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                let mut body = serde_json::json!({
                    "documents": policy_documents_payload(&req)?,
                    "force": req.force.unwrap_or(false),
                });
                if let Some(rev) = &req.base_revision {
                    body["baseRevision"] = serde_json::json!(rev);
                }
                let (status, value) = api
                    .post_json("/policy/apply", &body)
                    .await
                    .map_err(map_error)?;
                if status == 409 {
                    return Ok(json_payload(serde_json::json!({
                        "conflict": true,
                        "status": status,
                        "body": value,
                    })));
                }
                crate::policy_api::require_ok(status, &value, "policy apply").map_err(map_error)?;
                Ok(json_payload(value))
            }
            "drift" => {
                let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                let body = serde_json::json!({ "documents": policy_documents_payload(&req)? });
                let (status, value) = api
                    .post_json("/policy/drift", &body)
                    .await
                    .map_err(map_error)?;
                crate::policy_api::require_ok(status, &value, "policy drift").map_err(map_error)?;
                Ok(json_payload(value))
            }
            "history" => {
                let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                let (status, value) = api.get_json("/policy/history").await.map_err(map_error)?;
                crate::policy_api::require_ok(status, &value, "policy history")
                    .map_err(map_error)?;
                Ok(json_payload(value))
            }
            "rollback" => {
                let revision_id = req
                    .revision_id
                    .as_deref()
                    .ok_or_else(|| map_error("revision_id is required for rollback"))?;
                let api = crate::policy_api::PolicyApi::from_env().map_err(map_error)?;
                let body = serde_json::json!({ "revisionId": revision_id });
                let (status, value) = api
                    .post_json("/policy/rollback", &body)
                    .await
                    .map_err(map_error)?;
                crate::policy_api::require_ok(status, &value, "policy rollback")
                    .map_err(map_error)?;
                Ok(json_payload(value))
            }
            other => Err(map_error(format!("unknown policy op: {other}"))),
        }
    }

    async fn device_info(&self) -> Result<JsonPayload, ApiError> {
        let snap = tunnet_core::state::load_snapshot_cache(&self.paths);
        let mut labels = HashMap::new();
        let mut tags = Vec::new();
        let mut expires_at = None;
        if let Some(snap) = snap {
            labels = snap.labels;
            expires_at = snap.expires_at;
            if let Some(m) = snap.memberships.first() {
                tags = m.self_tags.clone();
            }
        }
        Ok(json_payload(serde_json::json!({
            "labels": labels,
            "tags": tags,
            "expires_at": expires_at,
        })))
    }
}
