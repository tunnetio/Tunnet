use std::collections::BTreeMap;

use chrono::Timelike;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::event::AuditEvent;

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Version of the canonical string format. Bump when adding fields.
pub const CURRENT_SCHEMA_VERSION: u8 = 1;

/// Build the canonical string that feeds into the HMAC.
/// RULE: once published, a canonical version is FROZEN FOREVER.
pub fn canonical_v1(event: &AuditEvent, prev_hash: &str) -> String {
    [
        "v1",
        &event.sequence_number.unwrap_or(0).to_string(),
        &event.organization_id,
        &event.category_uid.to_string(),
        &event.class_uid.to_string(),
        &event.activity_id.to_string(),
        &event.type_uid.to_string(),
        &event.severity_id.to_string(),
        &event.status_id.to_string(),
        &event
            .time
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        &event.message,
        &event.actor.actor_type,
        &event.actor.actor_id,
        event.actor.ip_address.as_deref().unwrap_or(""),
        &event.target.target_type,
        &event.target.target_id,
        event.network_id.as_deref().unwrap_or(""),
        event.group_id.as_deref().unwrap_or(""),
        event.trace_id.as_deref().unwrap_or(""),
        &canonical_json(&event.metadata),
        prev_hash,
    ]
    .join("|")
}

pub fn compute_entry_hash(hmac_key: &[u8], canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key can be any length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn canonical_json(value: &serde_json::Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::new(&mut buf);
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map.iter().collect();
            sorted
                .serialize(&mut ser)
                .expect("canonical json serialize");
        }
        other => {
            other.serialize(&mut ser).expect("canonical json serialize");
        }
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Apply hash chain fields to a contiguous org batch given the previous chain tip.
pub fn chain_events(
    hmac_key: &[u8],
    events: &mut [AuditEvent],
    start_seq: i64,
    start_prev_hash: &str,
) {
    let mut seq = start_seq;
    let mut prev_hash = start_prev_hash.to_string();
    for event in events.iter_mut() {
        // Truncate to whole seconds so DB round-trip matches the canonical string.
        event.time = event.time.with_nanosecond(0).unwrap_or(event.time);
        seq += 1;
        event.sequence_number = Some(seq);
        event.prev_entry_hash = Some(prev_hash.clone());
        let canonical = canonical_v1(event, &prev_hash);
        let hash = compute_entry_hash(hmac_key, &canonical);
        event.entry_hash = Some(hash.clone());
        event.hmac_schema_version = CURRENT_SCHEMA_VERSION;
        prev_hash = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{ACTIVITY_CREATE, DEVICE_ACTIVITY};
    use crate::event::{Actor, Target};

    #[test]
    fn hash_is_deterministic() {
        let mut e = AuditEvent::new(
            "org_1",
            DEVICE_ACTIVITY,
            ACTIVITY_CREATE,
            "device registered",
            Actor {
                actor_type: "system".into(),
                actor_id: "control".into(),
                display_name: None,
                email: None,
                ip_address: None,
                user_agent: None,
            },
            Target {
                target_type: "device".into(),
                target_id: "ep_1".into(),
                display_name: None,
            },
        );
        e.sequence_number = Some(1);
        e.time = chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let c1 = canonical_v1(&e, GENESIS_HASH);
        let c2 = canonical_v1(&e, GENESIS_HASH);
        assert_eq!(c1, c2);
        let h1 = compute_entry_hash(b"test-key-at-least-32-bytes-long!!", &c1);
        let h2 = compute_entry_hash(b"test-key-at-least-32-bytes-long!!", &c2);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
