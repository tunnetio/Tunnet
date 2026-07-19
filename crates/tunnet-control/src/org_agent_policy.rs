//! Persist agent-reported effective configuration for the dashboard.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tunnet_common::EffectiveAgentConfig;

pub async fn store_effective_config(
    pool: &PgPool,
    endpoint_id: &str,
    config: &EffectiveAgentConfig,
    reported_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let config_json = serde_json::to_value(config)?;
    let reported = reported_at.to_rfc3339();
    sqlx::query(
        "UPDATE devices SET metadata = jsonb_set(
            jsonb_set(COALESCE(metadata, '{}'::jsonb), '{effectiveConfig}', $2::jsonb, true),
            '{effectiveConfigReportedAt}', to_jsonb($3::text), true
         ), last_seen = now()
         WHERE endpoint_id = $1",
    )
    .bind(endpoint_id)
    .bind(config_json)
    .bind(reported)
    .execute(pool)
    .await?;
    Ok(())
}
