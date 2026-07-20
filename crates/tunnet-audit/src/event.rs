use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::class::{CATEGORY_AUDIT, SEVERITY_INFO, STATUS_SUCCESS, type_uid};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub category_uid: u16,
    pub class_uid: u16,
    pub activity_id: u8,
    pub type_uid: u32,
    pub severity_id: u8,
    pub status_id: u8,
    pub time: DateTime<Utc>,
    pub message: String,

    pub actor: Actor,
    pub target: Target,

    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<Diff>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_entry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    #[serde(default)]
    pub hmac_schema_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub actor_type: String,
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub target_type: String,
    pub target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub before: Value,
    pub after: Value,
}

/// Ingest payload from management / internal callers (hash fields omitted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIngestEvent {
    pub organization_id: String,
    pub class_uid: u16,
    pub activity_id: u8,
    #[serde(default = "default_severity")]
    pub severity_id: u8,
    #[serde(default = "default_status")]
    pub status_id: u8,
    pub message: String,
    pub actor: Actor,
    pub target: Target,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub diff: Option<Diff>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub time: Option<DateTime<Utc>>,
}

fn default_severity() -> u8 {
    SEVERITY_INFO
}

fn default_status() -> u8 {
    STATUS_SUCCESS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIngestRequest {
    #[serde(default)]
    pub events: Vec<AuditIngestEvent>,
}

impl From<AuditIngestEvent> for AuditEvent {
    fn from(e: AuditIngestEvent) -> Self {
        let class_uid = e.class_uid;
        let activity_id = e.activity_id;
        Self {
            category_uid: CATEGORY_AUDIT,
            class_uid,
            activity_id,
            type_uid: type_uid(class_uid, activity_id),
            severity_id: e.severity_id,
            status_id: e.status_id,
            time: e.time.unwrap_or_else(Utc::now),
            message: e.message,
            actor: e.actor,
            target: e.target,
            organization_id: e.organization_id,
            network_id: e.network_id,
            group_id: e.group_id,
            diff: e.diff,
            metadata: e.metadata,
            trace_id: e.trace_id,
            sequence_number: None,
            prev_entry_hash: None,
            entry_hash: None,
            hmac_schema_version: 0,
        }
    }
}

impl AuditEvent {
    pub fn new(
        organization_id: impl Into<String>,
        class_uid: u16,
        activity_id: u8,
        message: impl Into<String>,
        actor: Actor,
        target: Target,
    ) -> Self {
        Self {
            category_uid: CATEGORY_AUDIT,
            class_uid,
            activity_id,
            type_uid: type_uid(class_uid, activity_id),
            severity_id: SEVERITY_INFO,
            status_id: STATUS_SUCCESS,
            time: Utc::now(),
            message: message.into(),
            actor,
            target,
            organization_id: organization_id.into(),
            network_id: None,
            group_id: None,
            diff: None,
            metadata: Value::Object(Default::default()),
            trace_id: None,
            sequence_number: None,
            prev_entry_hash: None,
            entry_hash: None,
            hmac_schema_version: 0,
        }
    }
}
