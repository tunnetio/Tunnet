use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;
use tunnet_common::policy::{
    Action, PolicyBundle, PolicyRule, Protocol, Selector, SshAction, SshPolicyRule,
};
use tunnet_common::posture::PostureEnforcementConfig;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct Row {
    src_selector: sqlx::types::Json<Selector>,
    dst_selector: sqlx::types::Json<Selector>,
    action: String,
    ports: sqlx::types::Json<Vec<tunnet_common::policy::PortRange>>,
    protocol: Option<String>,
    priority: i32,
    src_posture: Option<sqlx::types::Json<Vec<String>>>,
}

#[derive(sqlx::FromRow)]
struct SshRow {
    src_selector: sqlx::types::Json<Selector>,
    dst_selector: sqlx::types::Json<Selector>,
    action: String,
    users: sqlx::types::Json<Vec<String>>,
    record: bool,
    recorder: Option<sqlx::types::Json<Selector>>,
    enforce_recorder: bool,
    check_period_secs: Option<i64>,
    priority: i32,
}

#[derive(sqlx::FromRow)]
struct PostureDefinitionRow {
    name: String,
    assertions: sqlx::types::Json<Vec<String>>,
}

pub async fn load_network_bundle(
    pool: &PgPool,
    signing_key: &SigningKey,
    network_id: Uuid,
    version: u64,
) -> anyhow::Result<PolicyBundle> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT src_selector, dst_selector, action, ports, protocol, priority, src_posture \
         FROM policies WHERE network_id = $1 ORDER BY priority DESC",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    let ssh_rows: Vec<SshRow> = sqlx::query_as(
        "SELECT src_selector, dst_selector, action, users, record, recorder, \
                enforce_recorder, check_period_secs, priority \
         FROM ssh_policies WHERE network_id = $1 ORDER BY priority DESC",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    let org_id: String = sqlx::query_scalar("SELECT organization_id FROM networks WHERE id = $1")
        .bind(network_id)
        .fetch_one(pool)
        .await?;

    let posture_meta = load_posture_metadata(pool, &org_id, Some(network_id)).await?;
    sign_bundle(
        signing_key,
        rows,
        ssh_rows,
        version,
        posture_meta.postures,
        posture_meta.default_src_posture,
        posture_meta.posture_enforcement,
    )
}

pub async fn load_org_bundle(
    pool: &PgPool,
    signing_key: &SigningKey,
    organization_id: &str,
    version: u64,
) -> anyhow::Result<PolicyBundle> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT src_selector, dst_selector, action, ports, protocol, priority, src_posture \
         FROM policies \
         WHERE organization_id = $1 AND network_id IS NULL \
         ORDER BY priority DESC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;

    // Org-level SSH rules are not modeled yet; network-scoped only.
    let posture_meta = load_posture_metadata(pool, organization_id, None).await?;
    sign_bundle(
        signing_key,
        rows,
        Vec::new(),
        version,
        posture_meta.postures,
        posture_meta.default_src_posture,
        posture_meta.posture_enforcement,
    )
}

struct PostureMetadata {
    postures: HashMap<String, Vec<String>>,
    default_src_posture: Vec<String>,
    posture_enforcement: Option<PostureEnforcementConfig>,
}

/// Load posture defs + settings with inheritance: network ← org ← empty/defaults.
async fn load_posture_metadata(
    pool: &PgPool,
    organization_id: &str,
    network_id: Option<Uuid>,
) -> anyhow::Result<PostureMetadata> {
    // Org-level definitions first.
    let org_defs: Vec<PostureDefinitionRow> = sqlx::query_as(
        "SELECT name, assertions FROM posture_definitions \
         WHERE organization_id = $1 AND network_id IS NULL",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut postures: HashMap<String, Vec<String>> = org_defs
        .into_iter()
        .map(|d| (d.name, d.assertions.0))
        .collect();

    if let Some(nid) = network_id {
        let net_defs: Vec<PostureDefinitionRow> = sqlx::query_as(
            "SELECT name, assertions FROM posture_definitions \
             WHERE organization_id = $1 AND network_id = $2",
        )
        .bind(organization_id)
        .bind(nid)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        for d in net_defs {
            postures.insert(d.name, d.assertions.0);
        }
    }

    let org_settings = crate::posture::load_settings_row(pool, organization_id, None)
        .await
        .unwrap_or(None);

    let net_settings = if let Some(nid) = network_id {
        crate::posture::load_settings_row(pool, organization_id, Some(nid))
            .await
            .unwrap_or(None)
    } else {
        None
    };

    // Network row fully replaces org row when present (simple inheritance).
    let settings = net_settings.or(org_settings);

    let (default_src_posture, posture_enforcement) = match settings {
        Some(s) => {
            let default_src_posture = s.default_src_posture.0.clone();
            (default_src_posture, Some(crate::posture::to_enforcement(s)))
        }
        None => (Vec::new(), None),
    };

    Ok(PostureMetadata {
        postures,
        default_src_posture,
        posture_enforcement,
    })
}

fn sign_bundle(
    signing_key: &SigningKey,
    rows: Vec<Row>,
    ssh_rows: Vec<SshRow>,
    version: u64,
    postures: HashMap<String, Vec<String>>,
    default_src_posture: Vec<String>,
    posture_enforcement: Option<PostureEnforcementConfig>,
) -> anyhow::Result<PolicyBundle> {
    let rules = rows
        .into_iter()
        .map(|r| PolicyRule {
            src: r.src_selector.0,
            dst: r.dst_selector.0,
            action: if r.action == "allow" {
                Action::Allow
            } else {
                Action::Deny
            },
            ports: r.ports.0,
            protocol: r.protocol.and_then(|p| match p.as_str() {
                "tcp" => Some(Protocol::Tcp),
                "udp" => Some(Protocol::Udp),
                "icmp" => Some(Protocol::Icmp),
                "any" => Some(Protocol::Any),
                _ => None,
            }),
            priority: r.priority,
            src_posture: {
                let explicit = r.src_posture.map(|j| j.0).unwrap_or_default();
                if explicit.is_empty() {
                    default_src_posture.clone()
                } else {
                    explicit
                }
            },
        })
        .collect::<Vec<_>>();

    let ssh_rules = ssh_rows
        .into_iter()
        .filter_map(|r| {
            let action = match r.action.as_str() {
                "accept" => SshAction::Accept,
                "check" => SshAction::Check,
                "deny" => SshAction::Deny,
                _ => return None,
            };
            Some(SshPolicyRule {
                src: r.src_selector.0,
                dst: r.dst_selector.0,
                action,
                users: r.users.0,
                record: r.record,
                recorder: r.recorder.map(|j| j.0),
                enforce_recorder: r.enforce_recorder,
                check_period_secs: r.check_period_secs.map(|s| s as u64),
                priority: r.priority,
            })
        })
        .collect::<Vec<_>>();

    let mut bundle = PolicyBundle {
        rules,
        ssh_rules,
        version,
        signature: String::new(),
        postures,
        default_src_posture,
        posture_enforcement,
    };
    let sign_bytes = serde_json::to_vec(&(&bundle.rules, &bundle.ssh_rules, bundle.version))?;
    let sig = signing_key.sign(&sign_bytes);
    bundle.signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());
    Ok(bundle)
}

#[allow(dead_code)]
fn _touch<'de, T: Deserialize<'de>>() {}
