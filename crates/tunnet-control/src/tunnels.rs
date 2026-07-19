//! Agent-facing tunnel create / lifecycle + relay register / heartbeat.

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AuthError, authenticate};
use crate::state::SharedState;
use crate::token_hash::hash_token;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

type ActiveTunnelRow = (
    Uuid,
    String,
    String,
    i32,
    String,
    Option<String>,
    Option<String>,
    Uuid,
);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayRegisterBody {
    pub endpoint_id: String,
    pub public_ip: Option<String>,
    #[serde(default)]
    pub agent_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayRegisterResponse {
    pub relay_id: String,
    pub name: String,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayHeartbeatBody {
    pub endpoint_id: String,
    #[serde(default)]
    pub active_tunnels: u32,
    /// ISO-8601 cert notAfter from the relay TLS cert, when known.
    #[serde(default)]
    pub cert_valid_until: Option<String>,
}

fn bearer_token(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string))
}

#[allow(clippy::type_complexity)]
pub async fn relay_register_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let token = match bearer_token(&req) {
        Some(t) => t,
        None => return err(StatusCode::UNAUTHORIZED, "missing Bearer token"),
    };
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let body: RelayRegisterBody = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if body.endpoint_id.len() != 64 || !body.endpoint_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(StatusCode::BAD_REQUEST, "invalid endpoint_id");
    }

    let token_hash = hash_token(&token);
    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };

    let row: Option<(Uuid, String, String, Option<chrono::DateTime<chrono::Utc>>)> =
        match sqlx::query_as(
            "SELECT t.relay_id, r.name, r.domain, t.used_at \
             FROM relay_registration_tokens t \
             JOIN relays r ON r.id = t.relay_id \
             WHERE t.token_hash = $1 AND t.expires_at > now()",
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        };

    let Some((relay_id, name, domain, used_at)) = row else {
        return err(StatusCode::UNAUTHORIZED, "invalid or expired relay token");
    };

    // First use claims the token; reconnects with the same token are allowed
    // when the endpoint id matches the stored public_key.
    if used_at.is_some() {
        let existing: Option<String> =
            match sqlx::query_scalar("SELECT public_key FROM relays WHERE id = $1")
                .bind(relay_id)
                .fetch_optional(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
            };
        if existing.as_deref() != Some(body.endpoint_id.as_str()) {
            return err(StatusCode::UNAUTHORIZED, "relay token already used");
        }
    }

    if let Err(e) = sqlx::query(
        "UPDATE relays SET public_key = $2, status = 'healthy', \
         last_heartbeat_at = now(), updated_at = now(), \
         public_ip = COALESCE($3::inet, public_ip) \
         WHERE id = $1",
    )
    .bind(relay_id)
    .bind(&body.endpoint_id)
    .bind(body.public_ip.as_deref())
    .execute(&mut *tx)
    .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    if used_at.is_none()
        && let Err(e) = sqlx::query(
            "UPDATE relay_registration_tokens SET used_at = now() WHERE token_hash = $1",
        )
        .bind(&token_hash)
        .execute(&mut *tx)
        .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    if let Err(e) = tx.commit().await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    let _ = body.agent_version;
    (
        StatusCode::OK,
        Json(RelayRegisterResponse {
            relay_id: relay_id.to_string(),
            name,
            domain,
        }),
    )
        .into_response()
}

pub async fn relay_heartbeat_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let token = match bearer_token(&req) {
        Some(t) => t,
        None => return err(StatusCode::UNAUTHORIZED, "missing Bearer token"),
    };
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let body: RelayHeartbeatBody = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };

    let token_hash = hash_token(&token);
    let relay_id: Option<Uuid> = match sqlx::query_scalar(
        "SELECT r.id FROM relays r \
         JOIN relay_registration_tokens t ON t.relay_id = r.id \
         WHERE t.token_hash = $1 AND r.public_key = $2 \
           AND r.status <> 'disabled'",
    )
    .bind(&token_hash)
    .bind(&body.endpoint_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };

    let Some(relay_id) = relay_id else {
        return err(StatusCode::UNAUTHORIZED, "unknown relay");
    };

    if let Err(e) = sqlx::query(
        "UPDATE relays SET last_heartbeat_at = now(), active_tunnels = $2, \
         status = 'healthy', updated_at = now(), \
         metadata = CASE \
           WHEN $3::text IS NOT NULL THEN \
             COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('certValidUntil', to_jsonb($3::text)) \
           ELSE metadata \
         END \
         WHERE id = $1",
    )
    .bind(relay_id)
    .bind(body.active_tunnels as i32)
    .bind(body.cert_valid_until.as_deref())
    .execute(&state.pool)
    .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    if let Err(e) =
        sqlx::query("INSERT INTO relay_heartbeats (relay_id, active_tunnels) VALUES ($1, $2)")
            .bind(relay_id)
            .bind(body.active_tunnels as i32)
            .execute(&state.pool)
            .await
    {
        tracing::warn!(?e, %relay_id, "failed to record relay heartbeat history");
    }

    if let Ok(Some(org_id)) =
        sqlx::query_scalar::<_, String>("SELECT organization_id FROM relays WHERE id = $1")
            .bind(relay_id)
            .fetch_optional(&state.pool)
            .await
    {
        let _ =
            crate::entity_notify::emit_relay_changed(&state.pool, &org_id, &relay_id.to_string())
                .await;
    }

    let tunnels: Vec<ActiveTunnelRow> = match sqlx::query_as(
        "SELECT t.id, t.subdomain, s.relay_auth_token, t.local_port, t.protocol, \
                t.basic_auth_user, t.basic_auth_password_hash, t.network_id \
         FROM tunnels t \
         JOIN tunnel_secrets s ON s.tunnel_id = t.id \
         WHERE t.relay_id = $1 AND t.status IN ('connecting', 'active')",
    )
    .bind(relay_id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };

    let mut tunnel_auth: Vec<serde_json::Value> = Vec::with_capacity(tunnels.len());
    for (
        tunnel_id,
        subdomain,
        auth_token,
        local_port,
        protocol,
        basic_auth_user,
        basic_auth_password_hash,
        network_id,
    ) in tunnels
    {
        let redirect_rules: Vec<(String, i32, Option<String>, Option<ipnetwork::IpNetwork>)> =
            match sqlx::query_as(
                "SELECT r.path_pattern, r.target_port, r.target_endpoint_id, m.assigned_ip \
                 FROM tunnel_routing_rules r \
                 LEFT JOIN network_memberships m \
                   ON m.endpoint_id = r.target_endpoint_id \
                  AND m.network_id = $2 \
                  AND m.status = 'active' \
                 WHERE r.tunnel_id = $1 AND r.kind = 'path' \
                 ORDER BY r.priority DESC, r.created_at ASC",
            )
            .bind(tunnel_id)
            .bind(network_id)
            .fetch_all(&state.pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(?e, %tunnel_id, "failed to load redirect rules for heartbeat");
                    Vec::new()
                }
            };

        let port_mappings: Vec<(i32, i32, Option<String>, Option<ipnetwork::IpNetwork>)> =
            match sqlx::query_as(
                "SELECT r.external_port, r.target_port, r.target_endpoint_id, m.assigned_ip \
                 FROM tunnel_routing_rules r \
                 LEFT JOIN network_memberships m \
                   ON m.endpoint_id = r.target_endpoint_id \
                  AND m.network_id = $2 \
                  AND m.status = 'active' \
                 WHERE r.tunnel_id = $1 AND r.kind = 'port' \
                 ORDER BY r.external_port ASC",
            )
            .bind(tunnel_id)
            .bind(network_id)
            .fetch_all(&state.pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(?e, %tunnel_id, "failed to load port mappings for heartbeat");
                    Vec::new()
                }
            };

        tunnel_auth.push(json!({
            "tunnelId": tunnel_id.to_string(),
            "subdomain": subdomain,
            "authToken": auth_token,
            "localPort": local_port,
            "protocol": protocol,
            "basicAuthUser": basic_auth_user,
            "basicAuthPasswordHash": basic_auth_password_hash,
            "redirectRules": redirect_rules.into_iter().map(|(path_pattern, target_port, _endpoint, assigned_ip)| {
                let mut rule = json!({
                    "pathPattern": path_pattern,
                    "targetPort": target_port,
                });
                if let Some(ip) = assigned_ip {
                    rule["targetIpv4"] = json!(ip.ip().to_string());
                }
                rule
            }).collect::<Vec<_>>(),
            "portMappings": port_mappings.into_iter().map(|(external_port, target_port, _endpoint, assigned_ip)| {
                let mut mapping = json!({
                    "externalPort": external_port,
                    "targetPort": target_port,
                });
                if let Some(ip) = assigned_ip {
                    mapping["targetIpv4"] = json!(ip.ip().to_string());
                }
                mapping
            }).collect::<Vec<_>>(),
        }));
    }

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "tunnels": tunnel_auth })),
    )
        .into_response()
}

// ---------- Agent tunnel create / lifecycle ----------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTunnelBody {
    pub local_port: u16,
    #[serde(default = "default_https")]
    pub protocol: String,
    pub subdomain: Option<String>,
    /// Relay UUID, name, or omit for auto.
    pub relay: Option<String>,
}

fn default_https() -> String {
    "https".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTunnelResponse {
    pub tunnel_id: String,
    pub subdomain: String,
    pub public_hostname: String,
    pub protocol: String,
    pub local_port: u16,
    pub relay_endpoint_id: String,
    pub relay_domain: String,
    pub auth_token: String,
    #[serde(default)]
    pub redirect_rules: Vec<tunnet_common::RedirectRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelLifecycleBody {
    pub tunnel_id: String,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn create_tunnel_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: CreateTunnelBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if body.local_port == 0 {
        return err(StatusCode::BAD_REQUEST, "invalid local_port");
    }
    if body.protocol != "https" && body.protocol != "tcp" {
        return err(StatusCode::BAD_REQUEST, "protocol must be https or tcp");
    }

    let membership: Option<(Uuid,)> = match sqlx::query_as(
        "SELECT network_id FROM network_memberships \
         WHERE endpoint_id = $1 AND status = 'active' LIMIT 1",
    )
    .bind(&auth.endpoint_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let Some((network_id,)) = membership else {
        return err(StatusCode::FORBIDDEN, "no active network membership");
    };

    let hostname: String = match sqlx::query_scalar(
        "SELECT COALESCE(metadata->>'hostname', 'app') FROM devices WHERE endpoint_id = $1",
    )
    .bind(&auth.endpoint_id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };

    let relay_row: Option<(Uuid, String, Option<String>)> = match &body.relay {
        Some(spec) if Uuid::parse_str(spec).is_ok() => {
            let id = Uuid::parse_str(spec).unwrap();
            match sqlx::query_as(
                "SELECT id, domain, public_key FROM relays \
                 WHERE id = $1 AND organization_id = $2 \
                   AND status IN ('healthy', 'pending')",
            )
            .bind(id)
            .bind(&auth.organization_id)
            .fetch_optional(&state.pool)
            .await
            {
                Ok(r) => r,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
            }
        }
        Some(name) => match sqlx::query_as(
            "SELECT id, domain, public_key FROM relays \
             WHERE organization_id = $1 AND name = $2 \
               AND status IN ('healthy', 'pending')",
        )
        .bind(&auth.organization_id)
        .bind(name)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        },
        None => match sqlx::query_as(
            "SELECT id, domain, public_key FROM relays \
             WHERE organization_id = $1 AND status = 'healthy' \
             ORDER BY last_heartbeat_at DESC NULLS LAST LIMIT 1",
        )
        .bind(&auth.organization_id)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(r) => r,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
        },
    };

    let Some((relay_id, relay_domain, relay_endpoint)) = relay_row else {
        return err(
            StatusCode::CONFLICT,
            "no healthy relay - register one with tunnet-relay register",
        );
    };
    let Some(relay_endpoint_id) = relay_endpoint.filter(|s| !s.is_empty()) else {
        return err(
            StatusCode::CONFLICT,
            "relay has not registered yet (missing public key)",
        );
    };

    let settings: Option<(Option<i32>, Option<String>)> = match sqlx::query_as(
        "SELECT max_tunnels_per_machine, custom_tunnel_domain \
         FROM organization_tunnel_settings WHERE organization_id = $1",
    )
    .bind(&auth.organization_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let max_tunnels = settings.as_ref().and_then(|(m, _)| *m).unwrap_or(10).max(1) as i64;
    let active_count: i64 = match sqlx::query_scalar(
        "SELECT count(*)::bigint FROM tunnels \
         WHERE endpoint_id = $1 AND status IN ('active', 'connecting')",
    )
    .bind(&auth.endpoint_id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    if active_count >= max_tunnels {
        return err(
            StatusCode::CONFLICT,
            &format!(
                "machine already has {active_count} tunnels (limit {max_tunnels} per machine)"
            ),
        );
    }

    let host = hostname
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(40)
        .collect::<String>();
    let subdomain = body
        .subdomain
        .unwrap_or_else(|| if host.is_empty() { "app".into() } else { host });
    let base_domain = settings
        .as_ref()
        .and_then(|(_, d)| d.as_ref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or(relay_domain);
    let public_hostname = format!("{subdomain}.{base_domain}");

    let mut token_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut token_bytes);
    let auth_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
    let auth_hash = hash_token(&auth_token);

    let tunnel_id: Uuid = match sqlx::query_scalar(
        "INSERT INTO tunnels \
           (organization_id, network_id, endpoint_id, relay_id, local_port, protocol, \
            subdomain, public_hostname, status, relay_auth_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'connecting', $9) \
         RETURNING id",
    )
    .bind(&auth.organization_id)
    .bind(network_id)
    .bind(&auth.endpoint_id)
    .bind(relay_id)
    .bind(body.local_port as i32)
    .bind(&body.protocol)
    .bind(&subdomain)
    .bind(&public_hostname)
    .bind(&auth_hash)
    .fetch_one(&state.pool)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("tunnels_organization_subdomain_unique") {
                return err(StatusCode::CONFLICT, "subdomain already in use");
            }
            return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
        }
    };

    if let Err(e) =
        sqlx::query("INSERT INTO tunnel_secrets (tunnel_id, relay_auth_token) VALUES ($1, $2)")
            .bind(tunnel_id)
            .bind(&auth_token)
            .execute(&state.pool)
            .await
    {
        let _ = sqlx::query("DELETE FROM tunnels WHERE id = $1")
            .bind(tunnel_id)
            .execute(&state.pool)
            .await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }

    let _ = crate::pg_notify::emit_network_changed(&state.pool, network_id).await;

    let redirect_rules = load_redirect_rules(&state.pool, tunnel_id).await;

    (
        StatusCode::OK,
        Json(CreateTunnelResponse {
            tunnel_id: tunnel_id.to_string(),
            subdomain,
            public_hostname,
            protocol: body.protocol,
            local_port: body.local_port,
            relay_endpoint_id,
            relay_domain: base_domain,
            auth_token,
            redirect_rules,
        }),
    )
        .into_response()
}

async fn load_redirect_rules(
    pool: &sqlx::PgPool,
    tunnel_id: Uuid,
) -> Vec<tunnet_common::RedirectRule> {
    let rows: Vec<(String, i32, Option<ipnetwork::IpNetwork>)> = match sqlx::query_as(
        "SELECT r.path_pattern, r.target_port, m.assigned_ip \
         FROM tunnel_routing_rules r \
         JOIN tunnels t ON t.id = r.tunnel_id \
         LEFT JOIN network_memberships m \
           ON m.endpoint_id = r.target_endpoint_id \
          AND m.network_id = t.network_id \
          AND m.status = 'active' \
         WHERE r.tunnel_id = $1 AND r.kind = 'path' \
         ORDER BY r.priority DESC, r.created_at ASC",
    )
    .bind(tunnel_id)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(?e, %tunnel_id, "failed to load redirect rules");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|(path_pattern, target_port, assigned_ip)| {
            u16::try_from(target_port).ok().map(|target_port| {
                let target_ipv4 = assigned_ip.and_then(|ip| match ip.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                });
                tunnet_common::RedirectRule {
                    path_pattern,
                    target_port,
                    target_ipv4,
                }
            })
        })
        .collect()
}

// ---------- Agent subnet route advertise ----------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubnetRouteBody {
    pub cidr: String,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn create_subnet_route_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: CreateSubnetRouteBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };

    let cidr: ipnet::Ipv4Net = match body.cidr.parse() {
        Ok(c) => c,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid cidr"),
    };

    let membership: Option<(Uuid,)> = match sqlx::query_as(
        "SELECT network_id FROM network_memberships \
         WHERE endpoint_id = $1 AND status = 'active' LIMIT 1",
    )
    .bind(&auth.endpoint_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let Some((network_id,)) = membership else {
        return err(StatusCode::FORBIDDEN, "no active network membership");
    };

    let route_id: Uuid = match sqlx::query_scalar(
        "INSERT INTO subnet_routes (endpoint_id, network_id, cidr, description, enabled) \
         VALUES ($1, $2, $3::cidr, $4, true) \
         ON CONFLICT (network_id, cidr) DO UPDATE \
           SET endpoint_id = EXCLUDED.endpoint_id, \
               description = COALESCE(EXCLUDED.description, subnet_routes.description), \
               enabled = true \
         RETURNING id",
    )
    .bind(&auth.endpoint_id)
    .bind(network_id)
    .bind(cidr.to_string())
    .bind(body.description.as_deref())
    .fetch_one(&state.pool)
    .await
    {
        Ok(id) => id,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };

    let _ = crate::pg_notify::emit_network_changed(&state.pool, network_id).await;

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "id": route_id.to_string(),
            "cidr": cidr.to_string(),
            "networkId": network_id.to_string(),
        })),
    )
        .into_response()
}

pub async fn tunnel_ready_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    tunnel_status_update(state, req, "active", None).await
}

pub async fn tunnel_stopped_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    tunnel_status_update(state, req, "stopped", None).await
}

pub async fn tunnel_failed_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: TunnelLifecycleBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    tunnel_status_update_inner(
        &state,
        &auth.endpoint_id,
        &body.tunnel_id,
        "error",
        body.error.as_deref(),
    )
    .await
}

async fn tunnel_status_update(
    state: SharedState,
    req: Request<Body>,
    status: &str,
    error: Option<&str>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let auth = match authenticate(&state, req, &method, &path).await {
        Ok(a) => a,
        Err(AuthError(c, m)) => return err(c, m),
    };
    let body: TunnelLifecycleBody = match serde_json::from_slice(&auth.body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    tunnel_status_update_inner(&state, &auth.endpoint_id, &body.tunnel_id, status, error).await
}

async fn tunnel_status_update_inner(
    state: &SharedState,
    endpoint_id: &str,
    tunnel_id: &str,
    status: &str,
    error: Option<&str>,
) -> Response {
    let res = sqlx::query(
        "UPDATE tunnels SET status = $3, error_message = $4, updated_at = now() \
         WHERE id = $1::uuid AND endpoint_id = $2",
    )
    .bind(tunnel_id)
    .bind(endpoint_id)
    .bind(status)
    .bind(error)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => err(StatusCode::NOT_FOUND, "tunnel not found"),
        Ok(_) => {
            let _ = crate::entity_notify::notify_tunnel_status(&state.pool, tunnel_id).await;
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    }
}

// ---------- Relay traffic ingest ----------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrafficLogLine {
    pub tunnel_id: String,
    pub method: String,
    pub path: String,
    pub status_code: i32,
    pub latency_ms: i32,
    pub source_ip: Option<String>,
    #[serde(default)]
    pub request_headers: serde_json::Value,
    #[serde(default)]
    pub response_headers: serde_json::Value,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrafficIngestBody {
    pub logs: Vec<RelayTrafficLogLine>,
}

pub async fn relay_traffic_handler(
    State(state): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let token = match bearer_token(&req) {
        Some(t) => t,
        None => return err(StatusCode::UNAUTHORIZED, "missing Bearer token"),
    };
    let body_bytes = match axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let body: RelayTrafficIngestBody = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid json"),
    };
    if body.logs.is_empty() {
        return err(StatusCode::BAD_REQUEST, "logs must not be empty");
    }
    if body.logs.len() > 500 {
        return err(StatusCode::BAD_REQUEST, "too many log lines (max 500)");
    }

    let token_hash = hash_token(&token);
    let relay_row: Option<(Uuid, String)> = match sqlx::query_as(
        "SELECT r.id, r.organization_id FROM relays r \
         JOIN relay_registration_tokens t ON t.relay_id = r.id \
         WHERE t.token_hash = $1 AND r.status <> 'disabled' \
         LIMIT 1",
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let Some((relay_id, organization_id)) = relay_row else {
        return err(StatusCode::UNAUTHORIZED, "unknown relay");
    };

    let mut inserted = 0u32;
    for line in &body.logs {
        let tunnel_id = match Uuid::parse_str(&line.tunnel_id) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let ok: Option<(bool,)> = match sqlx::query_as(
            "SELECT true FROM tunnels \
             WHERE id = $1 AND organization_id = $2 \
               AND (relay_id = $3 OR relay_id IS NULL)",
        )
        .bind(tunnel_id)
        .bind(&organization_id)
        .bind(relay_id)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, "traffic ingest tunnel lookup failed");
                continue;
            }
        };
        if ok.is_none() {
            continue;
        }

        let req_headers = if line.request_headers.is_null() {
            json!({})
        } else {
            line.request_headers.clone()
        };
        let res_headers = if line.response_headers.is_null() {
            json!({})
        } else {
            line.response_headers.clone()
        };

        let res = if let Some(at) = line.created_at {
            sqlx::query(
                "INSERT INTO tunnel_request_logs \
                   (tunnel_id, organization_id, method, path, status_code, latency_ms, \
                    source_ip, request_headers, response_headers, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(tunnel_id)
            .bind(&organization_id)
            .bind(&line.method)
            .bind(&line.path)
            .bind(line.status_code)
            .bind(line.latency_ms)
            .bind(line.source_ip.as_deref())
            .bind(&req_headers)
            .bind(&res_headers)
            .bind(at)
            .execute(&state.pool)
            .await
        } else {
            sqlx::query(
                "INSERT INTO tunnel_request_logs \
                   (tunnel_id, organization_id, method, path, status_code, latency_ms, \
                    source_ip, request_headers, response_headers) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(tunnel_id)
            .bind(&organization_id)
            .bind(&line.method)
            .bind(&line.path)
            .bind(line.status_code)
            .bind(line.latency_ms)
            .bind(line.source_ip.as_deref())
            .bind(&req_headers)
            .bind(&res_headers)
            .execute(&state.pool)
            .await
        };

        match res {
            Ok(_) => inserted += 1,
            Err(e) => tracing::warn!(?e, %tunnel_id, "failed to insert traffic log"),
        }
    }

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "inserted": inserted })),
    )
        .into_response()
}

/// Expire tunnels past TTL and push StopTunnel to agents.
pub async fn expire_tunnels(state: &SharedState) -> anyhow::Result<()> {
    let expired: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "UPDATE tunnels SET status = 'expired', updated_at = now() \
         WHERE expires_at IS NOT NULL AND expires_at < now() \
           AND status IN ('connecting', 'active') \
         RETURNING id, endpoint_id, network_id",
    )
    .fetch_all(&state.pool)
    .await?;

    for (tunnel_id, endpoint_id, network_id) in expired {
        state
            .ws_hub
            .push_to(
                &endpoint_id,
                tunnet_common::ws::ServerMsg::StopTunnel {
                    tunnel_id: tunnel_id.to_string(),
                },
            )
            .await;
        let _ = crate::pg_notify::emit_network_changed(&state.pool, network_id).await;
        let _ =
            crate::entity_notify::notify_tunnel_status(&state.pool, &tunnel_id.to_string()).await;
        tracing::info!(%tunnel_id, %endpoint_id, "tunnel expired by TTL");
    }
    Ok(())
}
