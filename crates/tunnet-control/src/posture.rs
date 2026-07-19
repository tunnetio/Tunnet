//! Device posture ingestion, evaluation, and enforcement state.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::PgPool;
use tunnet_common::posture::{PostureEnforcementConfig, PostureEvalResult};
use tunnet_common::ws::ServerMsg;
use tunnet_posture::{
    PostureAssertion, PostureScoringConfig, PostureValue, compute_posture_score,
    evaluate_named_postures, format_remediation_messages, parse_assertion,
    remediation_for_failures,
};
use uuid::Uuid;

use crate::state::AppState;
use crate::ws_hub::WsHub;

#[derive(Debug, Clone)]
pub struct PostureGraceState {
    pub started_at: DateTime<Utc>,
    pub grace_period_secs: u64,
}

pub type PostureGraceMap = Arc<DashMap<String, PostureGraceState>>;

pub fn grace_map() -> PostureGraceMap {
    Arc::new(DashMap::new())
}

#[derive(sqlx::FromRow)]
pub(crate) struct OrgPostureSettingsRow {
    pub mode: String,
    pub grace_period_minutes: i32,
    pub recheck_on_fail_seconds: i32,
    pub notify_user: bool,
    pub notify_admin: bool,
    pub auto_reauthorize: bool,
    pub default_src_posture: sqlx::types::Json<Vec<String>>,
}

#[derive(sqlx::FromRow)]
struct PostureDefinitionRow {
    name: String,
    assertions: sqlx::types::Json<Vec<String>>,
    id: uuid::Uuid,
}

pub async fn handle_posture_report(
    state: &AppState,
    endpoint_id: &str,
    full: bool,
    attributes: HashMap<String, serde_json::Value>,
    collected_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let org_id: Option<String> =
        sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(organization_id) = org_id else {
        tracing::warn!(%endpoint_id, "PostureReport for unknown device");
        return Ok(());
    };

    if full {
        sqlx::query(
            "DELETE FROM posture_attributes \
             WHERE endpoint_id = $1 AND source = 'agent'",
        )
        .bind(endpoint_id)
        .execute(&state.pool)
        .await?;
    }

    for (attr_key, value) in &attributes {
        let (namespace, key) = split_attribute_key(attr_key);
        sqlx::query(
            "INSERT INTO posture_attributes \
               (id, endpoint_id, organization_id, namespace, key, value, collected_at, source) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'agent') \
             ON CONFLICT (endpoint_id, namespace, key) DO UPDATE SET \
               value = EXCLUDED.value, \
               collected_at = EXCLUDED.collected_at, \
               source = EXCLUDED.source",
        )
        .bind(endpoint_id)
        .bind(&organization_id)
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(collected_at)
        .execute(&state.pool)
        .await?;
    }

    if let Some(public_ip) = load_public_ip(&state.pool, endpoint_id).await? {
        let ip_value = serde_json::json!(public_ip);
        sqlx::query(
            "INSERT INTO posture_attributes \
               (id, endpoint_id, organization_id, namespace, key, value, collected_at, source) \
             VALUES (gen_random_uuid(), $1, $2, 'ip', 'address', $3, $4, 'control') \
             ON CONFLICT (endpoint_id, namespace, key) DO UPDATE SET \
               value = EXCLUDED.value, \
               collected_at = EXCLUDED.collected_at, \
               source = EXCLUDED.source",
        )
        .bind(endpoint_id)
        .bind(&organization_id)
        .bind(&ip_value)
        .bind(Utc::now())
        .execute(&state.pool)
        .await?;
    }

    let merged = load_device_attributes(&state.pool, endpoint_id).await?;
    let network_ids = load_active_network_ids(&state.pool, endpoint_id).await?;
    let definitions =
        load_inherited_posture_definitions(&state.pool, &organization_id, &network_ids).await?;
    let settings =
        load_inherited_posture_settings(&state.pool, &organization_id, &network_ids).await?;

    let definition_map = parse_posture_definitions(&definitions);
    let posture_names: Vec<String> = definitions.iter().map(|d| d.name.clone()).collect();
    let summary = evaluate_named_postures(&definition_map, &posture_names, &merged);
    let score = compute_posture_score(&merged, &PostureScoringConfig::default_weights());

    for def in &definitions {
        if let Some(result) = summary.results.get(&def.name) {
            let failing: Vec<String> = result
                .failing_assertions
                .iter()
                .map(|a| format!("{} {:?}", a.attribute, a.operator))
                .collect();
            sqlx::query(
                "INSERT INTO posture_evaluations \
                   (id, endpoint_id, organization_id, posture_definition_id, passed, \
                    failing_assertions, score, evaluated_at) \
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, now())",
            )
            .bind(endpoint_id)
            .bind(&organization_id)
            .bind(def.id)
            .bind(result.passed)
            .bind(sqlx::types::Json(&failing))
            .bind(score as i32)
            .execute(&state.pool)
            .await?;
        }
    }

    let (enforcement_action, grace_remaining, remediation_messages) =
        compute_enforcement(&state.posture_grace, endpoint_id, &summary, &settings);

    let postures: Vec<PostureEvalResult> = summary
        .results
        .into_iter()
        .map(|(name, result)| PostureEvalResult {
            name,
            passed: result.passed,
            failing_assertions: result
                .failing_assertions
                .iter()
                .map(|a| format!("{} {:?}", a.attribute, a.operator))
                .collect(),
        })
        .collect();

    state
        .ws_hub
        .push_to(
            endpoint_id,
            ServerMsg::PostureStatus {
                postures,
                enforcement_action: enforcement_action.clone(),
                grace_period_remaining_secs: grace_remaining,
                remediation_messages: remediation_messages.clone(),
            },
        )
        .await;

    tracing::debug!(
        %endpoint_id,
        %enforcement_action,
        score,
        "posture evaluation complete"
    );
    Ok(())
}

fn parse_posture_definitions(
    definitions: &[PostureDefinitionRow],
) -> HashMap<String, Vec<PostureAssertion>> {
    definitions
        .iter()
        .map(|d| {
            let assertions = d
                .assertions
                .0
                .iter()
                .filter_map(|raw| parse_assertion(raw).ok())
                .collect();
            (d.name.clone(), assertions)
        })
        .collect()
}

fn compute_enforcement(
    grace_map: &PostureGraceMap,
    endpoint_id: &str,
    summary: &tunnet_posture::PostureEvalSummary,
    settings: &PostureEnforcementConfig,
) -> (String, Option<u64>, Vec<String>) {
    let all_failures: Vec<PostureAssertion> = summary
        .results
        .values()
        .flat_map(|r| r.failing_assertions.clone())
        .collect();
    let remediation = format_remediation_messages(
        &remediation_for_failures(&all_failures),
        Some(settings.grace_period_minutes),
    );

    if summary.passed {
        grace_map.remove(endpoint_id);
        return ("allow".into(), None, remediation);
    }

    match settings.mode.as_str() {
        "monitor" => ("allow".into(), None, remediation),
        "warn" => ("warn".into(), None, remediation),
        "enforce" => {
            let grace_secs = settings.grace_period_minutes as u64 * 60;
            let entry =
                grace_map
                    .entry(endpoint_id.to_string())
                    .or_insert_with(|| PostureGraceState {
                        started_at: Utc::now(),
                        grace_period_secs: grace_secs,
                    });
            let elapsed = (Utc::now() - entry.started_at).num_seconds().max(0) as u64;
            if elapsed >= entry.grace_period_secs {
                ("revoke".into(), Some(0), remediation)
            } else {
                (
                    "grace".into(),
                    Some(entry.grace_period_secs - elapsed),
                    remediation,
                )
            }
        }
        _ => ("allow".into(), None, remediation),
    }
}

pub async fn load_device_attributes(
    pool: &PgPool,
    endpoint_id: &str,
) -> anyhow::Result<HashMap<String, PostureValue>> {
    let rows: Vec<(String, String, sqlx::types::Json<serde_json::Value>)> = sqlx::query_as(
        "SELECT namespace, key, value FROM posture_attributes WHERE endpoint_id = $1",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await?;

    let mut out = HashMap::new();
    for (namespace, key, value) in rows {
        let attr_key = if namespace.is_empty() {
            key
        } else {
            format!("{namespace}:{key}")
        };
        if let Ok(parsed) = serde_json::from_value::<PostureValue>(value.0) {
            out.insert(attr_key, parsed);
        }
    }
    Ok(out)
}

async fn load_public_ip(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<Option<String>> {
    let ip: Option<String> =
        sqlx::query_scalar("SELECT host(public_ip) FROM devices WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_optional(pool)
            .await?;
    Ok(ip.filter(|s| !s.is_empty()))
}

async fn load_active_network_ids(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT network_id FROM network_memberships \
         WHERE endpoint_id = $1 AND status = 'active'",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Org defs plus network overrides (same name → network wins).
async fn load_inherited_posture_definitions(
    pool: &PgPool,
    organization_id: &str,
    network_ids: &[Uuid],
) -> anyhow::Result<Vec<PostureDefinitionRow>> {
    let org_rows: Vec<PostureDefinitionRow> = sqlx::query_as(
        "SELECT id, name, assertions FROM posture_definitions \
         WHERE organization_id = $1 AND network_id IS NULL",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;

    let mut by_name: HashMap<String, PostureDefinitionRow> =
        org_rows.into_iter().map(|r| (r.name.clone(), r)).collect();

    for network_id in network_ids {
        let net_rows: Vec<PostureDefinitionRow> = sqlx::query_as(
            "SELECT id, name, assertions FROM posture_definitions \
             WHERE organization_id = $1 AND network_id = $2",
        )
        .bind(organization_id)
        .bind(network_id)
        .fetch_all(pool)
        .await?;
        for row in net_rows {
            by_name.insert(row.name.clone(), row);
        }
    }

    Ok(by_name.into_values().collect())
}

pub(crate) async fn load_settings_row(
    pool: &PgPool,
    organization_id: &str,
    network_id: Option<Uuid>,
) -> anyhow::Result<Option<OrgPostureSettingsRow>> {
    if let Some(nid) = network_id {
        Ok(sqlx::query_as(
            "SELECT mode, grace_period_minutes, recheck_on_fail_seconds, notify_user, \
                    notify_admin, auto_reauthorize, default_src_posture \
             FROM posture_org_settings \
             WHERE organization_id = $1 AND network_id = $2",
        )
        .bind(organization_id)
        .bind(nid)
        .fetch_optional(pool)
        .await?)
    } else {
        Ok(sqlx::query_as(
            "SELECT mode, grace_period_minutes, recheck_on_fail_seconds, notify_user, \
                    notify_admin, auto_reauthorize, default_src_posture \
             FROM posture_org_settings \
             WHERE organization_id = $1 AND network_id IS NULL",
        )
        .bind(organization_id)
        .fetch_optional(pool)
        .await?)
    }
}

fn mode_rank(mode: &str) -> u8 {
    match mode {
        "enforce" => 3,
        "warn" => 2,
        _ => 1,
    }
}

pub(crate) fn to_enforcement(row: OrgPostureSettingsRow) -> PostureEnforcementConfig {
    PostureEnforcementConfig {
        mode: row.mode,
        grace_period_minutes: row.grace_period_minutes.max(0) as u32,
        recheck_on_fail_secs: row.recheck_on_fail_seconds.max(0) as u64,
        notify_user: row.notify_user,
        notify_admin: row.notify_admin,
        auto_reauthorize: row.auto_reauthorize,
    }
}

/// Inherit settings per network (network ← org), then pick the strictest mode.
async fn load_inherited_posture_settings(
    pool: &PgPool,
    organization_id: &str,
    network_ids: &[Uuid],
) -> anyhow::Result<PostureEnforcementConfig> {
    let org = load_settings_row(pool, organization_id, None)
        .await?
        .map(to_enforcement)
        .unwrap_or_default();

    if network_ids.is_empty() {
        return Ok(org);
    }

    let mut best = org.clone();
    for nid in network_ids {
        let inherited = match load_settings_row(pool, organization_id, Some(*nid)).await? {
            Some(row) => to_enforcement(row),
            None => org.clone(),
        };
        if mode_rank(&inherited.mode) > mode_rank(&best.mode) {
            best = inherited;
        } else if mode_rank(&inherited.mode) == mode_rank(&best.mode) {
            // Same mode: prefer shorter grace / faster recheck from network row if present.
            best.grace_period_minutes = best
                .grace_period_minutes
                .min(inherited.grace_period_minutes);
            best.recheck_on_fail_secs = best
                .recheck_on_fail_secs
                .min(inherited.recheck_on_fail_secs);
            best.notify_admin = best.notify_admin || inherited.notify_admin;
            best.notify_user = best.notify_user || inherited.notify_user;
        }
    }
    Ok(best)
}

#[allow(dead_code)]
pub async fn load_org_posture_settings(
    pool: &PgPool,
    organization_id: &str,
) -> anyhow::Result<PostureEnforcementConfig> {
    Ok(load_settings_row(pool, organization_id, None)
        .await?
        .map(to_enforcement)
        .unwrap_or_default())
}

pub async fn request_posture_recheck(hub: &WsHub, endpoint_id: &str) {
    hub.push_to(endpoint_id, ServerMsg::PostureRecheck).await;
}

fn split_attribute_key(attr_key: &str) -> (&str, &str) {
    match attr_key.split_once(':') {
        Some((ns, key)) => (ns, key),
        None => ("custom", attr_key),
    }
}

pub fn json_attributes(
    attrs: &HashMap<String, PostureValue>,
) -> HashMap<String, serde_json::Value> {
    attrs
        .iter()
        .filter_map(|(k, v)| serde_json::to_value(v).ok().map(|j| (k.clone(), j)))
        .collect()
}
