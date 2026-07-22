//! Re-issue OpenTunnel / StartServe when an agent WebSocket reconnects.
//!
//! Snapshot deliberately omits `relay_auth_token`; TunnelManager only starts
//! connections when it receives `ServerMsg::OpenTunnel` with the real token
//! loaded from `tunnel_secrets`.

use sqlx::PgPool;
use tunnet_common::ws::ServerMsg;
use uuid::Uuid;

use crate::ca_crypto;
use crate::state::SharedState;
use crate::ws_hub::WsHub;

pub async fn replay_endpoint_workloads(state: &SharedState, endpoint_id: &str) {
    if let Err(e) = replay_tunnels(&state.pool, &state.ws_hub, endpoint_id).await {
        tracing::warn!(?e, %endpoint_id, "tunnel replay on reconnect failed");
    }
    let ca_key = ca_crypto::resolve_ca_key(state.args.ca_encryption_key.as_deref());
    if let Err(e) = replay_serves(&state.pool, &state.ws_hub, endpoint_id, &ca_key).await {
        tracing::warn!(?e, %endpoint_id, "serve replay on reconnect failed");
    }
}

#[allow(clippy::type_complexity)]
async fn replay_tunnels(pool: &PgPool, hub: &WsHub, endpoint_id: &str) -> anyhow::Result<()> {
    let rows: Vec<(
        Uuid,
        i32,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT t.id, t.local_port, t.protocol, t.subdomain, t.public_hostname, \
                s.relay_auth_token, r.public_key \
         FROM tunnels t \
         LEFT JOIN tunnel_secrets s ON s.tunnel_id = t.id \
         LEFT JOIN relays r ON r.id = t.relay_id \
         WHERE t.endpoint_id = $1 AND t.status IN ('active', 'connecting')",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await?;

    for (tunnel_id, local_port, protocol, subdomain, public_hostname, auth_token, relay_addr) in
        rows
    {
        let Some(auth_token) = auth_token.filter(|t| !t.is_empty()) else {
            tracing::warn!(%tunnel_id, %endpoint_id, "skip OpenTunnel replay: missing relay_auth_token");
            continue;
        };
        let Some(relay_addr) = relay_addr.filter(|a| !a.is_empty()) else {
            tracing::warn!(%tunnel_id, %endpoint_id, "skip OpenTunnel replay: relay missing public_key");
            let _ = sqlx::query(
                "UPDATE tunnels SET status = 'error', \
                 error_message = $2, updated_at = now() \
                 WHERE id = $1",
            )
            .bind(tunnel_id)
            .bind("Relay has no public key - cannot re-open tunnel on reconnect")
            .execute(pool)
            .await;
            continue;
        };

        let redirect_rules = load_redirect_rules(pool, tunnel_id).await;
        let local_port = match u16::try_from(local_port) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%tunnel_id, local_port, "skip OpenTunnel replay: invalid port");
                continue;
            }
        };

        hub.push_to(
            endpoint_id,
            ServerMsg::OpenTunnel {
                tunnel_id: tunnel_id.to_string(),
                relay_addr,
                subdomain,
                public_hostname,
                local_port,
                protocol,
                auth_token,
                redirect_rules,
                target_addr: None,
            },
        )
        .await;
        tracing::info!(%tunnel_id, %endpoint_id, "re-pushed OpenTunnel on reconnect");
    }
    Ok(())
}

async fn load_redirect_rules(pool: &PgPool, tunnel_id: Uuid) -> Vec<tunnet_common::RedirectRule> {
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
            tracing::warn!(?e, %tunnel_id, "failed to load redirect rules for replay");
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

#[allow(clippy::type_complexity)]
async fn replay_serves(
    pool: &PgPool,
    hub: &WsHub,
    endpoint_id: &str,
    ca_key: &[u8; 32],
) -> anyhow::Result<()> {
    let rows: Vec<(
        Uuid,
        i32,
        String,
        String,
        String,
        Vec<String>,
        Vec<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT s.id, s.local_port, s.protocol, s.internal_hostname, s.access_mode, \
                s.allowed_tags, s.allowed_endpoint_ids, \
                c.certificate_pem, c.encrypted_private_key \
         FROM serves s \
         LEFT JOIN internal_certificates c ON c.id = s.certificate_id \
         WHERE s.endpoint_id = $1 AND s.status IN ('active', 'starting')",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await?;

    let desired_ids: Vec<String> = rows.iter().map(|(id, ..)| id.to_string()).collect();
    hub.push_to(
        endpoint_id,
        ServerMsg::ReconcileServes {
            serve_ids: desired_ids,
        },
    )
    .await;

    for (
        serve_id,
        port,
        protocol,
        internal_hostname,
        access_mode,
        allowed_tags,
        allowed_endpoint_ids,
        certificate_pem,
        encrypted_private_key,
    ) in rows
    {
        let port = match u16::try_from(port) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%serve_id, port, "skip StartServe replay: invalid port");
                continue;
            }
        };

        let private_key_pem = match (&protocol, &encrypted_private_key) {
            (p, Some(blob)) if p != "tcp" => match ca_crypto::decrypt_pem(ca_key, blob) {
                Ok(pem) => Some(pem),
                Err(e) => {
                    tracing::warn!(?e, %serve_id, "skip StartServe replay: decrypt private key failed");
                    continue;
                }
            },
            _ => None,
        };

        if protocol != "tcp" && (certificate_pem.is_none() || private_key_pem.is_none()) {
            tracing::warn!(%serve_id, %endpoint_id, "skip StartServe replay: missing cert material");
            continue;
        }

        hub.push_to(
            endpoint_id,
            ServerMsg::StartServe {
                serve_id: serve_id.to_string(),
                port,
                protocol,
                internal_hostname,
                certificate_pem,
                private_key_pem,
                access_mode,
                allowed_tags,
                allowed_endpoint_ids,
                target_addr: None,
            },
        )
        .await;
        tracing::info!(%serve_id, %endpoint_id, "re-pushed StartServe on reconnect");
    }
    Ok(())
}
