//! Device posture ingestion, evaluation, and enforcement state.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use jiff::Timestamp;
use sqlx::{PgConnection, PgPool};
use tunnet_common::posture::{
    POSTURE_RECEIPT_BOUND_SECS, PeerPosture, PostureEnforcementConfig, PostureEvalResult,
};
use tunnet_common::ws::ServerMsg;
use tunnet_posture::{
    PostureAssertion, PostureScoringConfig, PostureValue, compute_posture_score, evaluate_posture,
    format_remediation_messages, parse_assertion, remediation_for_failures,
};
use uuid::Uuid;

use crate::state::AppState;
use crate::ws_hub::WsHub;

#[derive(Debug, Clone)]
pub enum PostureGraceState {
    Compliant {
        revision: i64,
        received_at: Timestamp,
    },
    Failing {
        revision: i64,
        received_at: Timestamp,
        started_at: Timestamp,
    },
}

impl PostureGraceState {
    fn revision(&self) -> i64 {
        match self {
            Self::Compliant { revision, .. } | Self::Failing { revision, .. } => *revision,
        }
    }

    fn received_at(&self) -> Timestamp {
        match self {
            Self::Compliant { received_at, .. } | Self::Failing { received_at, .. } => *received_at,
        }
    }
}

pub type PostureGraceMap = Arc<DashMap<(String, Option<Uuid>), PostureGraceState>>;

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
    collected_at: Timestamp,
) -> anyhow::Result<()> {
    let _agent_clock = collected_at;
    let mut transaction = state.pool.begin().await?;
    let org_id: Option<String> =
        sqlx::query_scalar("SELECT organization_id FROM devices WHERE endpoint_id = $1 FOR UPDATE")
            .bind(endpoint_id)
            .fetch_optional(&mut *transaction)
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
        .execute(&mut *transaction)
        .await?;
    }

    for (attr_key, value) in &attributes {
        let (namespace, key) = split_attribute_key(attr_key);
        anyhow::ensure!(
            !matches!(namespace, "ip" | "control"),
            "reserved posture attribute namespace"
        );
        sqlx::query(
            "INSERT INTO posture_attributes \
               (id, endpoint_id, organization_id, namespace, key, value, collected_at, expires_at, source) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, statement_timestamp(), \
                     statement_timestamp() + make_interval(secs => $6::int), 'agent') \
             ON CONFLICT (endpoint_id, namespace, key) DO UPDATE SET \
               value = EXCLUDED.value, \
               collected_at = statement_timestamp(), \
               expires_at = statement_timestamp() + make_interval(secs => $6::int), \
               source = EXCLUDED.source",
        )
        .bind(endpoint_id)
        .bind(&organization_id)
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(POSTURE_RECEIPT_BOUND_SECS as i32)
        .execute(&mut *transaction)
        .await?;
    }

    if let Some(public_ip) = load_public_ip(&mut transaction, endpoint_id).await? {
        let ip_value = serde_json::json!(public_ip);
        sqlx::query(
            "INSERT INTO posture_attributes \
               (id, endpoint_id, organization_id, namespace, key, value, collected_at, expires_at, source) \
             VALUES (gen_random_uuid(), $1, $2, 'ip', 'address', $3, statement_timestamp(), \
                     statement_timestamp() + make_interval(secs => $4::int), 'control') \
             ON CONFLICT (endpoint_id, namespace, key) DO UPDATE SET \
               value = EXCLUDED.value, \
               collected_at = statement_timestamp(), \
               expires_at = statement_timestamp() + make_interval(secs => $4::int), \
               source = EXCLUDED.source",
        )
        .bind(endpoint_id)
        .bind(&organization_id)
        .bind(&ip_value)
        .bind(POSTURE_RECEIPT_BOUND_SECS as i32)
        .execute(&mut *transaction)
        .await?;
    }

    let evidence = load_attribute_evidence(&mut transaction, endpoint_id).await?;
    let network_ids = load_active_network_ids(&mut transaction, endpoint_id).await?;
    let now = server_now(&mut transaction).await?;
    let mut enforcement_scopes = Vec::new();
    let mut postures: Vec<PostureEvalResult> = Vec::new();
    let scopes: Vec<Option<Uuid>> = if network_ids.is_empty() {
        vec![None]
    } else {
        network_ids.iter().copied().map(Some).collect()
    };
    for network_id in scopes {
        let definitions =
            load_scoped_definition_rows(&mut transaction, &organization_id, network_id).await?;
        let (settings, required) =
            inherited_settings(&mut transaction, &organization_id, network_id).await?;
        let raw: HashMap<String, Vec<String>> = definitions
            .iter()
            .map(|definition| (definition.name.clone(), definition.assertions.0.clone()))
            .collect();
        let definition_map = parse_definition_map(&raw);
        let fresh = fresh_attribute_map(&evidence, now);
        let summary = scoped_summary(&raw, &definition_map, &evidence, &required, now);
        let score = compute_posture_score(&fresh, &PostureScoringConfig::default_weights());
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
                     VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, statement_timestamp())",
                )
                .bind(endpoint_id)
                .bind(&organization_id)
                .bind(def.id)
                .bind(result.passed)
                .bind(sqlx::types::Json(&failing))
                .bind(score as i32)
                .execute(&mut *transaction)
                .await?;
            }
        }
        postures.extend(summary.results.iter().map(|(name, result)| {
            PostureEvalResult {
                name: name.clone(),
                passed: result.passed,
                failing_assertions: result
                    .failing_assertions
                    .iter()
                    .map(|assertion| format!("{} {:?}", assertion.attribute, assertion.operator))
                    .collect(),
            }
        }));
        enforcement_scopes.push((network_id, summary, settings));
    }

    let revision = bump_posture_revision(&mut transaction, &organization_id).await?;
    transaction.commit().await?;
    let mut enforcement_action = "allow".to_string();
    let mut grace_remaining = None;
    let mut remediation_messages = Vec::new();
    for (network, summary, settings) in enforcement_scopes {
        let Some((action, grace, remediation)) = compute_enforcement(
            &state.posture_grace,
            endpoint_id,
            network,
            &summary,
            &settings,
            revision,
            now,
        ) else {
            return Ok(());
        };
        if action_rank(&action) > action_rank(&enforcement_action) {
            enforcement_action = action;
            grace_remaining = grace;
            remediation_messages = remediation;
        }
    }

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
        "posture evaluation complete"
    );
    Ok(())
}

fn compute_enforcement(
    grace_map: &PostureGraceMap,
    endpoint_id: &str,
    network_id: Option<Uuid>,
    summary: &tunnet_posture::PostureEvalSummary,
    settings: &PostureEnforcementConfig,
    revision: i64,
    received_at: Timestamp,
) -> Option<(String, Option<u64>, Vec<String>)> {
    let now = Timestamp::now();
    if received_at > now
        || now >= received_at + jiff::SignedDuration::from_secs(POSTURE_RECEIPT_BOUND_SECS as i64)
    {
        return None;
    }
    let all_failures: Vec<PostureAssertion> = summary
        .results
        .values()
        .flat_map(|result| result.failing_assertions.clone())
        .collect();
    let remediation = format_remediation_messages(
        &remediation_for_failures(&all_failures),
        Some(settings.grace_period_minutes),
    );
    let scope = (endpoint_id.to_string(), network_id);
    let mut state = grace_map
        .entry(scope)
        .or_insert(PostureGraceState::Compliant {
            revision,
            received_at,
        });
    if state.revision() > revision {
        return None;
    }
    if summary.passed {
        *state = PostureGraceState::Compliant {
            revision,
            received_at,
        };
        return Some(("allow".into(), None, remediation));
    }
    let started_at = match &*state {
        PostureGraceState::Failing { started_at, .. } => *started_at,
        PostureGraceState::Compliant { .. } => received_at,
    };
    *state = PostureGraceState::Failing {
        revision,
        received_at,
        started_at,
    };
    Some(match settings.mode.as_str() {
        "monitor" => ("allow".into(), None, remediation),
        "warn" => ("warn".into(), None, remediation),
        "enforce" => {
            let grace_secs = u64::from(settings.grace_period_minutes) * 60;
            let elapsed = now.duration_since(started_at).as_secs().max(0) as u64;
            if elapsed >= grace_secs {
                ("revoke".into(), Some(0), remediation)
            } else {
                ("grace".into(), Some(grace_secs - elapsed), remediation)
            }
        }
        _ => ("revoke".into(), Some(0), remediation),
    })
}

pub async fn load_device_attributes(
    pool: &PgPool,
    endpoint_id: &str,
) -> anyhow::Result<HashMap<String, PostureValue>> {
    let mut connection = pool.acquire().await?;
    let evidence = load_attribute_evidence(&mut connection, endpoint_id).await?;
    let now = server_now(&mut connection).await?;
    Ok(fresh_attribute_map(&evidence, now))
}

async fn load_public_ip(
    pool: &mut PgConnection,
    endpoint_id: &str,
) -> anyhow::Result<Option<String>> {
    let ip: Option<String> = sqlx::query_scalar(
        "SELECT host(public_ip) FROM devices WHERE endpoint_id = $1 AND public_ip IS NOT NULL",
    )
    .bind(endpoint_id)
    .fetch_optional(&mut *pool)
    .await?;
    Ok(ip.filter(|s| !s.is_empty()))
}

async fn load_active_network_ids(
    pool: &mut PgConnection,
    endpoint_id: &str,
) -> anyhow::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT network_id FROM network_memberships \
         WHERE endpoint_id = $1 AND status = 'active'",
    )
    .bind(endpoint_id)
    .fetch_all(&mut *pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Org definitions overridden by one network. Other networks do not participate.
async fn load_scoped_definition_rows(
    pool: &mut PgConnection,
    organization_id: &str,
    network_id: Option<Uuid>,
) -> anyhow::Result<Vec<PostureDefinitionRow>> {
    let org_rows: Vec<PostureDefinitionRow> = sqlx::query_as(
        "SELECT id, name, assertions FROM posture_definitions \
         WHERE organization_id = $1 AND network_id IS NULL",
    )
    .bind(organization_id)
    .fetch_all(&mut *pool)
    .await?;
    let mut by_name: HashMap<String, PostureDefinitionRow> = org_rows
        .into_iter()
        .map(|row| (row.name.clone(), row))
        .collect();
    if let Some(network_id) = network_id {
        let net_rows: Vec<PostureDefinitionRow> = sqlx::query_as(
            "SELECT id, name, assertions FROM posture_definitions \
             WHERE organization_id = $1 AND network_id = $2",
        )
        .bind(organization_id)
        .bind(network_id)
        .fetch_all(&mut *pool)
        .await?;
        for row in net_rows {
            by_name.insert(row.name.clone(), row);
        }
    }
    Ok(by_name.into_values().collect())
}

pub(crate) async fn load_settings_row(
    pool: &mut PgConnection,
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
        .fetch_optional(&mut *pool)
        .await?)
    } else {
        Ok(sqlx::query_as(
            "SELECT mode, grace_period_minutes, recheck_on_fail_seconds, notify_user, \
                    notify_admin, auto_reauthorize, default_src_posture \
             FROM posture_org_settings \
             WHERE organization_id = $1 AND network_id IS NULL",
        )
        .bind(organization_id)
        .fetch_optional(&mut *pool)
        .await?)
    }
}

fn action_rank(action: &str) -> u8 {
    match action {
        "revoke" => 4,
        "grace" => 3,
        "warn" => 2,
        _ => 1,
    }
}

pub(crate) fn to_enforcement(
    row: OrgPostureSettingsRow,
) -> anyhow::Result<PostureEnforcementConfig> {
    anyhow::ensure!(
        matches!(row.mode.as_str(), "monitor" | "warn" | "enforce"),
        "invalid posture enforcement mode"
    );
    Ok(PostureEnforcementConfig {
        mode: row.mode,
        grace_period_minutes: row.grace_period_minutes.max(0) as u32,
        recheck_on_fail_secs: row.recheck_on_fail_seconds.max(0) as u64,
        notify_user: row.notify_user,
        notify_admin: row.notify_admin,
        auto_reauthorize: row.auto_reauthorize,
    })
}

/// Network settings replace the org row when that network has one.
async fn inherited_settings(
    pool: &mut PgConnection,
    organization_id: &str,
    network_id: Option<Uuid>,
) -> anyhow::Result<(PostureEnforcementConfig, Vec<String>)> {
    let org = load_settings_row(pool, organization_id, None).await?;
    let network = if let Some(network_id) = network_id {
        load_settings_row(pool, organization_id, Some(network_id)).await?
    } else {
        None
    };
    Ok(match network.or(org) {
        Some(row) => {
            let required = row.default_src_posture.0.clone();
            (to_enforcement(row)?, required)
        }
        None => (PostureEnforcementConfig::default(), Vec::new()),
    })
}

async fn server_now(pool: &mut PgConnection) -> anyhow::Result<Timestamp> {
    let micros: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM statement_timestamp()) * 1000000)::bigint")
            .fetch_one(pool)
            .await?;
    Ok(Timestamp::from_microsecond(micros)?)
}

async fn bump_posture_revision(
    pool: &mut PgConnection,
    organization_id: &str,
) -> anyhow::Result<i64> {
    let revision: i64 = sqlx::query_scalar("UPDATE organization SET snapshot_version = snapshot_version + 1 WHERE id = $1 RETURNING snapshot_version")
        .bind(organization_id)
        .fetch_one(&mut *pool)
        .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(crate::pg_notify::ORG_CHANNEL)
        .bind(organization_id)
        .execute(pool)
        .await?;
    Ok(revision)
}

pub async fn expire_posture_claims(state: &AppState) -> anyhow::Result<()> {
    let mut transaction = state.pool.begin().await?;
    let orgs: Vec<(String,)> = sqlx::query_as(
        "WITH doomed AS (DELETE FROM posture_attributes \
         WHERE expires_at <= statement_timestamp() \
         OR collected_at <= statement_timestamp() - make_interval(secs => $1::int) \
         OR collected_at > statement_timestamp() RETURNING organization_id) \
         SELECT DISTINCT organization_id FROM doomed ORDER BY organization_id",
    )
    .bind(POSTURE_RECEIPT_BOUND_SECS as i32)
    .fetch_all(&mut *transaction)
    .await?;
    for (organization_id,) in orgs {
        bump_posture_revision(&mut transaction, &organization_id).await?;
    }
    transaction.commit().await?;
    let cutoff =
        Timestamp::now() - jiff::SignedDuration::from_secs(2 * POSTURE_RECEIPT_BOUND_SECS as i64);
    let endpoints: Vec<String> = state
        .posture_grace
        .iter()
        .filter(|entry| entry.received_at() <= cutoff)
        .map(|entry| entry.key().0.clone())
        .collect();
    if !endpoints.is_empty() {
        let active: Vec<(String, Option<Uuid>)> = sqlx::query_as(
            "SELECT d.endpoint_id, nm.network_id FROM devices d \
             LEFT JOIN network_memberships nm ON nm.endpoint_id = d.endpoint_id AND nm.status = 'active' \
             WHERE d.endpoint_id = ANY($1) AND d.expired_at IS NULL",
        ).bind(&endpoints).fetch_all(&state.pool).await?;
        let active: std::collections::HashSet<_> = active.into_iter().collect();
        state.posture_grace.retain(|scope, entry| {
            entry.received_at() > cutoff
                || (matches!(entry, PostureGraceState::Failing { .. }) && active.contains(scope))
        });
    }
    Ok(())
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

/// One server-received attribute. The agent clock is not a field.
#[derive(Debug, Clone)]
pub struct AttributeEvidence {
    pub value: PostureValue,
    pub received_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

impl AttributeEvidence {
    fn receipt_deadline(&self) -> Timestamp {
        self.received_at + jiff::SignedDuration::from_secs(POSTURE_RECEIPT_BOUND_SECS as i64)
    }

    fn fresh(&self, now: Timestamp) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        self.received_at <= now && now < expires_at && now < self.receipt_deadline()
    }

    fn deadline(&self) -> Option<Timestamp> {
        let expires_at = self.expires_at?;
        let receipt = self.receipt_deadline();
        Some(if expires_at < receipt {
            expires_at
        } else {
            receipt
        })
    }
}

fn fresh_attribute_map(
    attributes: &HashMap<String, AttributeEvidence>,
    now: Timestamp,
) -> HashMap<String, PostureValue> {
    attributes
        .iter()
        .filter(|(_, evidence)| evidence.fresh(now))
        .map(|(key, evidence)| (key.clone(), evidence.value.clone()))
        .collect()
}

/// Org assertion strings overridden by one network's strings. Names do not cross networks.
pub fn merge_definition_strings(
    org: HashMap<String, Vec<String>>,
    network: HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    let mut merged = org;
    for (name, assertions) in network {
        merged.insert(name, assertions);
    }
    merged
}

fn parse_definition_map(
    raw: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<PostureAssertion>> {
    raw.iter()
        .filter_map(|(name, assertions)| {
            let mut parsed = Vec::with_capacity(assertions.len());
            for assertion in assertions {
                parsed.push(parse_assertion(assertion).ok()?);
            }
            Some((name.clone(), parsed))
        })
        .collect()
}

fn definition_passes(
    assertions: &[PostureAssertion],
    attributes: &HashMap<String, AttributeEvidence>,
    fresh: &HashMap<String, PostureValue>,
    now: Timestamp,
) -> bool {
    if assertions.is_empty() {
        return false;
    }
    for assertion in assertions {
        let Some(evidence) = attributes.get(&assertion.attribute) else {
            return false;
        };
        if !evidence.fresh(now) {
            return false;
        }
    }
    evaluate_posture(assertions, fresh).passed
}

fn definition_deadline(
    assertions: &[PostureAssertion],
    attributes: &HashMap<String, AttributeEvidence>,
) -> Option<Timestamp> {
    assertions
        .iter()
        .try_fold(None, |until: Option<Timestamp>, assertion| {
            let deadline = attributes.get(&assertion.attribute)?.deadline()?;
            Some(Some(
                until.map_or(deadline, |current| current.min(deadline)),
            ))
        })?
}

/// Named claim for one network's definitions and the server's fresh evidence.
pub fn network_claim(
    definitions: &HashMap<String, Vec<PostureAssertion>>,
    attributes: &HashMap<String, AttributeEvidence>,
    now: Timestamp,
) -> PeerPosture {
    let fresh = fresh_attribute_map(attributes, now);
    let mut passed = Vec::new();
    let mut until: Option<Timestamp> = None;
    for (name, assertions) in definitions {
        if !definition_passes(assertions, attributes, &fresh, now) {
            continue;
        }
        let Some(deadline) = definition_deadline(assertions, attributes) else {
            continue;
        };
        if now >= deadline {
            continue;
        }
        passed.push(name.clone());
        until = Some(match until {
            Some(current) if current < deadline => current,
            _ => deadline,
        });
    }
    match until {
        Some(valid_until) if !passed.is_empty() => PeerPosture::verified(passed, valid_until),
        _ => PeerPosture::Unknown,
    }
}

#[derive(sqlx::FromRow)]
struct AttributeRow {
    namespace: String,
    key: String,
    value: sqlx::types::Json<serde_json::Value>,
    received_us: i64,
    expires_us: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct EndpointAttributeRow {
    endpoint_id: String,
    #[sqlx(flatten)]
    attribute: AttributeRow,
}

pub async fn claims_for_network(
    pool: &mut PgConnection,
    organization_id: &str,
    raw_definitions: &HashMap<String, Vec<String>>,
    endpoint_ids: &[String],
) -> anyhow::Result<HashMap<String, PeerPosture>> {
    if endpoint_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let definitions = parse_definition_map(raw_definitions);
    let rows: Vec<EndpointAttributeRow> = sqlx::query_as(
        "SELECT endpoint_id, namespace, key, value, \
         (extract(epoch FROM collected_at) * 1000000)::bigint AS received_us, \
         (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_us \
         FROM posture_attributes WHERE organization_id = $1 AND endpoint_id = ANY($2)",
    )
    .bind(organization_id)
    .bind(endpoint_ids)
    .fetch_all(&mut *pool)
    .await?;
    let mut evidence: HashMap<String, HashMap<String, AttributeEvidence>> = HashMap::new();
    for row in rows {
        if let Some((attribute, value)) = parse_attribute_evidence(row.attribute) {
            evidence
                .entry(row.endpoint_id)
                .or_default()
                .insert(attribute, value);
        }
    }
    let now = server_now(pool).await?;
    Ok(endpoint_ids
        .iter()
        .map(|endpoint| {
            let claim = evidence
                .get(endpoint)
                .map(|attributes| network_claim(&definitions, attributes, now))
                .unwrap_or_default();
            (endpoint.clone(), claim)
        })
        .collect())
}

pub(crate) async fn load_attribute_evidence(
    pool: &mut PgConnection,
    endpoint_id: &str,
) -> anyhow::Result<HashMap<String, AttributeEvidence>> {
    let rows: Vec<AttributeRow> = sqlx::query_as(
        "SELECT namespace, key, value, \
                (extract(epoch FROM collected_at) * 1000000)::bigint AS received_us, \
                (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_us \
         FROM posture_attributes WHERE endpoint_id = $1",
    )
    .bind(endpoint_id)
    .fetch_all(&mut *pool)
    .await?;
    let mut out = HashMap::new();
    for row in rows {
        if let Some((attribute, value)) = parse_attribute_evidence(row) {
            out.insert(attribute, value);
        }
    }
    Ok(out)
}

fn parse_attribute_evidence(row: AttributeRow) -> Option<(String, AttributeEvidence)> {
    let AttributeRow {
        namespace,
        key,
        value,
        received_us,
        expires_us,
    } = row;
    let value = serde_json::from_value::<PostureValue>(value.0).ok()?;
    let received_at = Timestamp::from_microsecond(received_us).ok()?;
    let expires_at = expires_us.and_then(|micros| Timestamp::from_microsecond(micros).ok());
    let attribute = if namespace.is_empty() {
        key
    } else {
        format!("{namespace}:{key}")
    };
    Some((
        attribute,
        AttributeEvidence {
            value,
            received_at,
            expires_at,
        },
    ))
}

fn scoped_summary(
    raw: &HashMap<String, Vec<String>>,
    definitions: &HashMap<String, Vec<PostureAssertion>>,
    evidence: &HashMap<String, AttributeEvidence>,
    required: &[String],
    now: Timestamp,
) -> tunnet_posture::PostureEvalSummary {
    let fresh = fresh_attribute_map(evidence, now);
    let results: HashMap<String, tunnet_posture::PostureResult> = raw
        .keys()
        .map(|name| {
            let result = match definitions.get(name) {
                Some(assertions) => {
                    let mut result = evaluate_posture(assertions, &fresh);
                    result.passed = definition_passes(assertions, evidence, &fresh, now);
                    result
                }
                None => tunnet_posture::PostureResult {
                    passed: false,
                    failing_assertions: Vec::new(),
                },
            };
            (name.clone(), result)
        })
        .collect();
    let passed = required.is_empty()
        || required
            .iter()
            .any(|name| results.get(name).is_some_and(|result| result.passed));
    tunnet_posture::PostureEvalSummary { passed, results }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_posture::PostureValue;

    fn evidence(
        key: &str,
        value: PostureValue,
        received_at: Timestamp,
        ttl: i64,
    ) -> (String, AttributeEvidence) {
        (
            key.into(),
            AttributeEvidence {
                value,
                received_at,
                expires_at: Some(received_at + jiff::SignedDuration::from_secs(ttl)),
            },
        )
    }

    fn defs(name: &str, assertion: &str) -> HashMap<String, Vec<PostureAssertion>> {
        parse_definition_map(&HashMap::from([(name.into(), vec![assertion.into()])]))
    }

    #[test]
    fn same_posture_name_is_scoped_to_each_network() {
        let org = HashMap::from([("corp".into(), vec!["node:os == 'linux'".into()])]);
        let linux_net = HashMap::from([("corp".into(), vec!["node:os == 'linux'".into()])]);
        let windows_net = HashMap::from([("corp".into(), vec!["node:os == 'windows'".into()])]);
        let linux_defs = parse_definition_map(&merge_definition_strings(org.clone(), linux_net));
        let windows_defs = parse_definition_map(&merge_definition_strings(org, windows_net));
        let now = Timestamp::now();
        let attrs = HashMap::from([evidence(
            "node:os",
            PostureValue::String("linux".into()),
            now,
            POSTURE_RECEIPT_BOUND_SECS as i64,
        )]);
        let linux = network_claim(&linux_defs, &attrs, now);
        let windows = network_claim(&windows_defs, &attrs, now);
        assert!(linux.satisfies(&["corp".into()], now));
        assert!(!windows.satisfies(&["corp".into()], now));
        assert_ne!(linux.fingerprint(), windows.fingerprint());
    }

    #[test]
    fn receipt_bounds_freshness_and_a_failed_report_does_not_reuse_the_previous_claim() {
        let definitions = defs("corp", "device:diskEncryption == true");
        let now = Timestamp::now();
        let fresh = HashMap::from([evidence(
            "device:diskEncryption",
            PostureValue::Bool(true),
            now,
            86_400,
        )]);
        let good = network_claim(&definitions, &fresh, now);
        assert!(matches!(good, PeerPosture::Verified { .. }));

        let stale_receipt = HashMap::from([evidence(
            "device:diskEncryption",
            PostureValue::Bool(true),
            now - jiff::SignedDuration::from_secs(POSTURE_RECEIPT_BOUND_SECS as i64 + 1),
            86_400,
        )]);
        assert!(matches!(
            network_claim(&definitions, &stale_receipt, now),
            PeerPosture::Unknown
        ));

        let soon = now + jiff::SignedDuration::from_secs(30);
        let short_lived = HashMap::from([(
            "device:diskEncryption".into(),
            AttributeEvidence {
                value: PostureValue::Bool(true),
                received_at: now,
                expires_at: Some(soon),
            },
        )]);
        let claim = network_claim(&definitions, &short_lived, now);
        assert_eq!(claim.valid_until(), Some(soon));
        assert!(claim.expired(soon));

        let bad = HashMap::from([evidence(
            "device:diskEncryption",
            PostureValue::Bool(false),
            now,
            POSTURE_RECEIPT_BOUND_SECS as i64,
        )]);
        let denied = network_claim(&definitions, &bad, now);
        assert!(matches!(denied, PeerPosture::Unknown));
        let again = network_claim(
            &definitions,
            &fresh,
            now + jiff::SignedDuration::from_secs(5),
        );
        assert!(matches!(again, PeerPosture::Verified { .. }));
        assert_ne!(good.fingerprint(), denied.fingerprint());
        assert_eq!(good.fingerprint(), again.fingerprint());
    }

    #[rstest::rstest]
    #[case(-601, Some(86400))]
    #[case(1, Some(600))]
    #[case(0, None)]
    #[case(0, Some(0))]
    fn unknown_or_stale_evidence_cannot_authorize_negative_assertions(
        #[case] received_offset: i64,
        #[case] ttl: Option<i64>,
    ) {
        let now = Timestamp::now();
        let received_at = now + jiff::SignedDuration::from_secs(received_offset);
        let attributes = HashMap::from([(
            "node:os".into(),
            AttributeEvidence {
                value: PostureValue::String("linux".into()),
                received_at,
                expires_at: ttl.map(|ttl| received_at + jiff::SignedDuration::from_secs(ttl)),
            },
        )]);
        let definitions = defs("required", "node:os != 'windows'");
        assert_eq!(
            network_claim(&definitions, &attributes, now),
            PeerPosture::Unknown
        );
        assert_eq!(
            network_claim(&definitions, &HashMap::new(), now),
            PeerPosture::Unknown
        );
    }

    #[test]
    fn malformed_or_empty_definitions_and_missing_values_are_not_proof() {
        let now = Timestamp::now();
        let attributes = HashMap::from([evidence(
            "node:os",
            PostureValue::String("linux".into()),
            now,
            600,
        )]);
        for assertions in [
            Vec::new(),
            vec!["node:os == 'linux'".into(), "malformed assertion".into()],
            vec!["device:diskEncryption IS NOT SET".into()],
        ] {
            let raw = HashMap::from([("required".into(), assertions)]);
            let definitions = parse_definition_map(&raw);
            assert_eq!(
                network_claim(&definitions, &attributes, now),
                PeerPosture::Unknown
            );
            assert!(
                !scoped_summary(&raw, &definitions, &attributes, &["required".into()], now).passed
            );
        }
        assert!(
            parse_attribute_evidence(AttributeRow {
                namespace: "node".into(),
                key: "os".into(),
                value: sqlx::types::Json(serde_json::json!({"bad":"value"})),
                received_us: now.as_microsecond(),
                expires_us: None,
            })
            .is_none()
        );
    }

    #[test]
    fn enforcement_uses_configured_named_requirements_and_scoped_grace() {
        let now = Timestamp::now();
        let raw = HashMap::from([
            (
                "required".into(),
                vec!["device:diskEncryption == true".into()],
            ),
            ("unrelated".into(), vec!["node:os == 'linux'".into()]),
        ]);
        let definitions = parse_definition_map(&raw);
        let attributes = HashMap::from([
            evidence("device:diskEncryption", PostureValue::Bool(false), now, 600),
            evidence("node:os", PostureValue::String("linux".into()), now, 600),
        ]);
        let failed = scoped_summary(&raw, &definitions, &attributes, &["required".into()], now);
        assert!(!failed.passed);
        assert!(failed.results["unrelated"].passed);
        let passed = scoped_summary(&raw, &definitions, &attributes, &["unrelated".into()], now);
        assert!(passed.passed);
        assert!(scoped_summary(&raw, &definitions, &attributes, &[], now).passed);
        let grace = grace_map();
        let network_a = Uuid::new_v4();
        let network_b = Uuid::new_v4();
        grace.insert(
            ("peer".into(), Some(network_a)),
            PostureGraceState::Failing {
                revision: 1,
                received_at: now,
                started_at: now - jiff::SignedDuration::from_secs(61),
            },
        );
        let settings = PostureEnforcementConfig {
            mode: "enforce".into(),
            grace_period_minutes: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_enforcement(&grace, "peer", Some(network_b), &passed, &settings, 2, now)
                .unwrap()
                .0,
            "allow"
        );
        assert_eq!(
            compute_enforcement(&grace, "peer", Some(network_a), &failed, &settings, 3, now)
                .unwrap()
                .0,
            "revoke"
        );
        assert!(grace.contains_key(&("peer".into(), Some(network_a))));
        assert!(
            compute_enforcement(&grace, "peer", Some(network_a), &passed, &settings, 2, now)
                .is_none()
        );
        assert!(matches!(
            *grace.get(&("peer".into(), Some(network_a))).unwrap(),
            PostureGraceState::Failing { revision: 3, .. }
        ));
    }
}
