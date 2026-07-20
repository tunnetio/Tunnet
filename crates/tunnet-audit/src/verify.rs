//! Verify the per-org HMAC hash chain against Postgres.

use sqlx::{FromRow, PgPool};

use crate::chain::{GENESIS_HASH, canonical_v1, compute_entry_hash};
use crate::event::{Actor, AuditEvent, Target};

#[derive(Debug)]
pub struct VerifyReport {
    pub organization_id: String,
    pub events_verified: u64,
    pub first_sequence: Option<i64>,
    pub last_sequence: Option<i64>,
    pub first_time: Option<chrono::DateTime<chrono::Utc>>,
    pub last_time: Option<chrono::DateTime<chrono::Utc>>,
    pub broken_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(FromRow)]
struct AuditVerifyRow {
    sequence_number: i64,
    category_uid: i16,
    class_uid: i16,
    activity_id: i16,
    type_uid: i32,
    severity_id: i16,
    status_id: i16,
    time: chrono::DateTime<chrono::Utc>,
    message: String,
    actor_type: String,
    actor_id: String,
    actor_ip: Option<String>,
    target_type: String,
    target_id: String,
    network_id: Option<uuid::Uuid>,
    group_id: Option<String>,
    metadata: serde_json::Value,
    trace_id: Option<String>,
    prev_entry_hash: String,
    entry_hash: String,
    hmac_schema_version: i16,
}

pub async fn verify_org_chain(
    pool: &PgPool,
    hmac_key: &[u8],
    organization_id: &str,
) -> anyhow::Result<VerifyReport> {
    let rows: Vec<AuditVerifyRow> = sqlx::query_as(
        "SELECT sequence_number, category_uid, class_uid, activity_id, type_uid,
                severity_id, status_id, time, message,
                actor_type, actor_id, host(actor_ip) AS actor_ip,
                target_type, target_id, network_id, group_id, metadata, trace_id,
                prev_entry_hash, entry_hash, hmac_schema_version
         FROM audit_events
         WHERE organization_id = $1
         ORDER BY sequence_number ASC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;

    let mut report = VerifyReport {
        organization_id: organization_id.to_string(),
        events_verified: 0,
        first_sequence: None,
        last_sequence: None,
        first_time: None,
        last_time: None,
        broken_at: None,
        error: None,
    };

    if rows.is_empty() {
        return Ok(report);
    }

    let mut prev_hash = GENESIS_HASH.to_string();

    for (expected_seq, row) in (1i64..).zip(rows.iter()) {
        let seq = row.sequence_number;

        if seq != expected_seq {
            report.broken_at = Some(seq);
            report.error = Some(format!("sequence gap: expected {expected_seq}, got {seq}"));
            break;
        }

        if row.prev_entry_hash != prev_hash {
            report.broken_at = Some(seq);
            report.error = Some(format!("prev_entry_hash mismatch at sequence {seq}"));
            break;
        }

        let event = AuditEvent {
            category_uid: row.category_uid as u16,
            class_uid: row.class_uid as u16,
            activity_id: row.activity_id as u8,
            type_uid: row.type_uid as u32,
            severity_id: row.severity_id as u8,
            status_id: row.status_id as u8,
            time: row.time,
            message: row.message.clone(),
            actor: Actor {
                actor_type: row.actor_type.clone(),
                actor_id: row.actor_id.clone(),
                display_name: None,
                email: None,
                ip_address: row.actor_ip.clone(),
                user_agent: None,
            },
            target: Target {
                target_type: row.target_type.clone(),
                target_id: row.target_id.clone(),
                display_name: None,
            },
            organization_id: organization_id.to_string(),
            network_id: row.network_id.map(|u| u.to_string()),
            group_id: row.group_id.clone(),
            diff: None,
            metadata: row.metadata.clone(),
            trace_id: row.trace_id.clone(),
            sequence_number: Some(seq),
            prev_entry_hash: Some(row.prev_entry_hash.clone()),
            entry_hash: Some(row.entry_hash.clone()),
            hmac_schema_version: row.hmac_schema_version as u8,
        };

        if row.hmac_schema_version != 1 {
            report.broken_at = Some(seq);
            report.error = Some(format!(
                "unsupported hmac_schema_version {} at sequence {seq}",
                row.hmac_schema_version
            ));
            break;
        }

        let canonical = canonical_v1(&event, &prev_hash);
        let computed = compute_entry_hash(hmac_key, &canonical);
        if computed != row.entry_hash {
            report.broken_at = Some(seq);
            report.error = Some(format!("entry_hash mismatch at sequence {seq}"));
            break;
        }

        if report.first_sequence.is_none() {
            report.first_sequence = Some(seq);
            report.first_time = Some(row.time);
        }
        report.last_sequence = Some(seq);
        report.last_time = Some(row.time);
        report.events_verified += 1;
        prev_hash = row.entry_hash.clone();
    }

    Ok(report)
}
