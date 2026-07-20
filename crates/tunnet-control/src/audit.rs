//! Thin wrappers that emit OCSF audit events via `tunnet-audit`.

use serde_json::Value;
use tunnet_audit::{
    ACTIVITY_CREATE, ACTIVITY_DELETE, ACTIVITY_OTHER, ACTIVITY_UPDATE, Actor, AuditEmitter,
    AuditEvent, DEVICE_ACTIVITY, Target,
};

/// Legacy-style helper used by Rust call sites during the migration to OCSF.
pub fn log(
    emitter: &AuditEmitter,
    organization_id: Option<&str>,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    metadata: Value,
    trace_id: Option<&str>,
) {
    let Some(org_id) = organization_id else {
        tracing::warn!(action, "audit event missing organization_id; dropped");
        return;
    };

    let (class_uid, activity_id) = map_action(action);
    let message = format_message(action, actor, target);

    let mut event = AuditEvent::new(
        org_id,
        class_uid,
        activity_id,
        message,
        Actor {
            actor_type: if actor.is_some() {
                "device".into()
            } else {
                "system".into()
            },
            actor_id: actor.unwrap_or("system").to_string(),
            display_name: None,
            email: None,
            ip_address: None,
            user_agent: None,
        },
        Target {
            target_type: infer_target_type(action),
            target_id: target.unwrap_or("").to_string(),
            display_name: None,
        },
    );
    event.metadata = metadata;
    event.trace_id = trace_id.map(|s| s.to_string());
    emitter.emit(event);
}

fn map_action(action: &str) -> (u16, u8) {
    if action.contains("created") || action.contains("registered") || action.contains("joined") {
        (DEVICE_ACTIVITY, ACTIVITY_CREATE)
    } else if action.contains("deleted") || action.contains("purged") || action.contains("removed")
    {
        (DEVICE_ACTIVITY, ACTIVITY_DELETE)
    } else if action.contains("updated") || action.contains("expired") {
        (DEVICE_ACTIVITY, ACTIVITY_UPDATE)
    } else {
        (DEVICE_ACTIVITY, ACTIVITY_OTHER)
    }
}

fn infer_target_type(action: &str) -> String {
    if action.starts_with("device.") {
        "device".into()
    } else if action.starts_with("network.") {
        "network".into()
    } else {
        "entity".into()
    }
}

fn format_message(action: &str, actor: Option<&str>, target: Option<&str>) -> String {
    match (actor, target) {
        (Some(a), Some(t)) => format!("{action} by {a} on {t}"),
        (Some(a), None) => format!("{action} by {a}"),
        (None, Some(t)) => format!("{action} on {t}"),
        (None, None) => action.to_string(),
    }
}
