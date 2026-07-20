use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::chain::{GENESIS_HASH, chain_events};
use crate::event::AuditEvent;
use crate::sink::AuditSink;

pub struct PostgresPgSink {
    pool: PgPool,
    hmac_key: Vec<u8>,
}

impl PostgresPgSink {
    pub fn new(pool: PgPool, hmac_key: Vec<u8>) -> Self {
        Self { pool, hmac_key }
    }

    /// Chain + insert a batch for a single organization under an advisory lock.
    pub async fn flush_org_batch(
        &self,
        org_id: &str,
        events: &mut [AuditEvent],
    ) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        let lock_key = format!("tunnet:audit:{org_id}");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&lock_key)
            .execute(&mut *tx)
            .await?;

        let last: Option<(i64, String)> = sqlx::query_as(
            "SELECT sequence_number, entry_hash FROM audit_events \
             WHERE organization_id = $1 \
             ORDER BY sequence_number DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (start_seq, start_prev) = last.unwrap_or((0, GENESIS_HASH.to_string()));
        chain_events(&self.hmac_key, events, start_seq, &start_prev);

        for event in events.iter() {
            let network_id: Option<Uuid> = event
                .network_id
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok());

            let (diff_before, diff_after) = match &event.diff {
                Some(d) => (Some(&d.before), Some(&d.after)),
                None => (None, None),
            };

            sqlx::query(
                "INSERT INTO audit_events (
                    organization_id, sequence_number,
                    category_uid, class_uid, activity_id, type_uid,
                    severity_id, status_id, time, message,
                    actor_type, actor_id, actor_name, actor_email, actor_ip, actor_ua,
                    target_type, target_id, target_name,
                    network_id, group_id, diff_before, diff_after, metadata, trace_id,
                    prev_entry_hash, entry_hash, hmac_schema_version
                ) VALUES (
                    $1, $2,
                    $3, $4, $5, $6,
                    $7, $8, $9, $10,
                    $11, $12, $13, $14, $15::inet, $16,
                    $17, $18, $19,
                    $20, $21, $22, $23, $24, $25,
                    $26, $27, $28
                )",
            )
            .bind(&event.organization_id)
            .bind(event.sequence_number.unwrap_or(0))
            .bind(event.category_uid as i16)
            .bind(event.class_uid as i16)
            .bind(event.activity_id as i16)
            .bind(event.type_uid as i32)
            .bind(event.severity_id as i16)
            .bind(event.status_id as i16)
            .bind(event.time)
            .bind(&event.message)
            .bind(&event.actor.actor_type)
            .bind(&event.actor.actor_id)
            .bind(&event.actor.display_name)
            .bind(&event.actor.email)
            .bind(event.actor.ip_address.as_deref().filter(|s| !s.is_empty()))
            .bind(&event.actor.user_agent)
            .bind(&event.target.target_type)
            .bind(&event.target.target_id)
            .bind(&event.target.display_name)
            .bind(network_id)
            .bind(&event.group_id)
            .bind(diff_before)
            .bind(diff_after)
            .bind(&event.metadata)
            .bind(&event.trace_id)
            .bind(event.prev_entry_hash.as_deref().unwrap_or(""))
            .bind(event.entry_hash.as_deref().unwrap_or(""))
            .bind(event.hmac_schema_version as i16)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl AuditSink for PostgresPgSink {
    fn name(&self) -> &str {
        "postgres"
    }

    async fn write_batch(&self, events: &mut [AuditEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        // Caller must pass a single-org batch (worker groups first).
        let org_id = events[0].organization_id.clone();
        self.flush_org_batch(&org_id, events).await
    }

    async fn read_last_chain_state(&self, org_id: &str) -> anyhow::Result<Option<(i64, String)>> {
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT sequence_number, entry_hash FROM audit_events \
             WHERE organization_id = $1 \
             ORDER BY sequence_number DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}
