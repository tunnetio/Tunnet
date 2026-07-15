use sqlx::PgPool;
use tuntun_common::{
    ActiveServe, DeviceProfile, DnsConfig, EndpointSnapshot, ExitNodeInfo, HostnameRoute,
    Ipv6PeerEntry, NetworkMembershipSnapshot, PeerEntry, SplitTunnelMode, SubnetRoute,
    TunnelConfig,
};
use uuid::Uuid;

use crate::pg_inet::{self, PgIp};

type EndpointRow = (
    String,
    bool,
    i64,
    serde_json::Value,
    Option<chrono::DateTime<chrono::Utc>>,
);

pub async fn build_endpoint_snapshot(
    pool: &PgPool,
    policy_key: &ed25519_dalek::SigningKey,
    endpoint_id: &str,
) -> anyhow::Result<EndpointSnapshot> {
    let endpoint_row: Option<EndpointRow> = sqlx::query_as(
        "SELECT e.organization_id, e.ipv6_enabled, o.snapshot_version, e.labels, \
           CASE \
             WHEN e.expired_at IS NOT NULL THEN e.expired_at \
             WHEN COALESCE( \
               e.inactivity_ttl, \
               CASE \
                 WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
                 THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
                 ELSE NULL \
               END \
             ) IS NOT NULL \
             THEN e.last_seen + COALESCE( \
               e.inactivity_ttl, \
               CASE \
                 WHEN COALESCE((o.settings->'machines'->'autoCleanup'->>'enabled')::boolean, false) \
                 THEN (o.settings->'machines'->'autoCleanup'->>'inactivityAfter')::interval \
                 ELSE NULL \
               END \
             ) \
             ELSE NULL \
           END \
         FROM devices e \
         JOIN organization o ON o.id = e.organization_id \
         WHERE e.endpoint_id = $1",
    )
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await?;

    let (organization_id, ipv6_enabled, org_version, labels_value, expires_at) =
        endpoint_row.ok_or_else(|| anyhow::anyhow!("endpoint not found"))?;
    let labels = crate::device_labels::normalize_labels(&labels_value);
    let tenant_ipv6 = if ipv6_enabled {
        Some(tuntun_common::ipv6::derive_tenant_ipv6(endpoint_id)?)
    } else {
        None
    };

    let membership_rows: Vec<(Uuid, String, PgIp, i32, i64, String)> = sqlx::query_as(
        "SELECT nm.network_id, n.name, nm.assigned_ip::inet, n.mtu, n.version, \
            COALESCE(NULLIF(e.metadata->>'hostname', ''), left(e.endpoint_id, 8)) AS hostname \
         FROM network_memberships nm \
         JOIN networks n ON n.id = nm.network_id \
         JOIN devices e ON e.endpoint_id = nm.endpoint_id \
         WHERE nm.endpoint_id = $1 AND nm.status = 'active'",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await?;

    let mut memberships = Vec::with_capacity(membership_rows.len());
    for (network_id, network_name, assigned_ip, mtu, network_version, self_hostname) in
        membership_rows
    {
        let assigned_ipv4 = pg_inet::to_ipv4_addr(assigned_ip)?;
        let prefix = network_prefix(pool, network_id).await?;
        let ipv4_peers = load_ipv4_peers(pool, network_id, endpoint_id, &network_name).await?;
        let subnet_routes = load_subnet_routes(pool, network_id).await?;
        let hostname_routes = load_hostname_routes(pool, network_id).await?;
        let exit_nodes = load_exit_nodes(pool, network_id).await?;
        let device_profile = load_device_profile(pool, endpoint_id, network_id).await?;
        let active_serves = load_active_serves(pool, network_id)
            .await
            .unwrap_or_default();
        let tunnel_config = load_tunnel_config(pool, endpoint_id, network_id)
            .await
            .unwrap_or_default();
        let self_tags = load_device_tags(pool, endpoint_id).await?;
        let policy = crate::policy_store::load_network_bundle(
            pool,
            policy_key,
            network_id,
            network_version as u64,
        )
        .await?;
        let bootstrap = ipv4_peers
            .iter()
            .take(5)
            .map(|p| p.endpoint_id.clone())
            .collect();
        let gossip_topic_hex = hex::encode(blake3::hash(network_id.as_bytes()).as_bytes());
        memberships.push(NetworkMembershipSnapshot {
            network_id,
            network_name,
            assigned_ipv4,
            prefix,
            mtu: mtu as u16,
            ipv4_peers,
            subnet_routes,
            hostname_routes,
            dns: DnsConfig::default(),
            exit_nodes,
            device_profile,
            active_serves,
            tunnel_config,
            self_tags,
            self_hostname,
            policy,
            gossip_bootstrap: bootstrap,
            gossip_topic_hex,
            version: network_version as u64,
        });
    }

    let ipv6_peers = if ipv6_enabled {
        load_ipv6_peers(pool, &organization_id, endpoint_id).await?
    } else {
        vec![]
    };

    let org_policy = crate::policy_store::load_org_bundle(
        pool,
        policy_key,
        &organization_id,
        org_version as u64,
    )
    .await?;

    let org_ca_pem = load_org_ca_pem(pool, &organization_id).await.ok().flatten();

    Ok(EndpointSnapshot {
        ipv6_enabled,
        tenant_ipv6,
        memberships,
        ipv6_peers,
        org_policy,
        org_ca_pem,
        labels,
        expires_at: expires_at.map(|t| t.to_rfc3339()),
        version: org_version as u64,
    })
}

async fn load_org_ca_pem(pool: &PgPool, organization_id: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT certificate_pem FROM organization_cas \
         WHERE organization_id = $1 AND status = 'active'",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(pem,)| pem))
}

async fn load_active_serves(pool: &PgPool, network_id: Uuid) -> anyhow::Result<Vec<ActiveServe>> {
    let rows: Vec<(Uuid, String, i32, String, String)> = sqlx::query_as(
        "SELECT id, endpoint_id, local_port, protocol, internal_hostname \
         FROM serves \
         WHERE network_id = $1 AND status = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, endpoint_id, port, protocol, internal_hostname)| ActiveServe {
                id: id.to_string(),
                endpoint_id,
                hostname: internal_hostname
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_string(),
                port: port as u16,
                protocol,
                internal_hostname,
            },
        )
        .collect())
}

#[allow(clippy::type_complexity)]
async fn load_tunnel_config(
    pool: &PgPool,
    endpoint_id: &str,
    network_id: Uuid,
) -> anyhow::Result<Vec<TunnelConfig>> {
    let rows: Vec<(
        Uuid,
        i32,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT t.id, t.local_port, t.protocol, t.subdomain, t.public_hostname, \
                r.public_key, r.domain, t.status \
         FROM tunnels t \
         LEFT JOIN relays r ON r.id = t.relay_id \
         WHERE t.endpoint_id = $1 AND t.network_id = $2 \
           AND t.status IN ('connecting', 'active')",
    )
    .bind(endpoint_id)
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                local_port,
                protocol,
                subdomain,
                public_hostname,
                relay_endpoint,
                _relay_domain,
                status,
            )| TunnelConfig {
                id: id.to_string(),
                local_port: local_port as u16,
                protocol,
                subdomain,
                public_hostname,
                // iroh endpoint id of the relay (dial target). Domain is in public_hostname.
                relay_addr: relay_endpoint.unwrap_or_default(),
                // Deliberately blank: TunnelManager starts only on OpenTunnel.
                // On agent WS reconnect, control plane re-pushes OpenTunnel with
                // Snapshot never carries secrets; reconnect loads from tunnel_secrets.
                relay_auth_token: String::new(),
                status,
            },
        )
        .collect())
}

async fn network_prefix(pool: &PgPool, network_id: Uuid) -> anyhow::Result<u8> {
    let (cidr,): (PgIp,) = sqlx::query_as("SELECT cidr FROM networks WHERE id = $1")
        .bind(network_id)
        .fetch_one(pool)
        .await?;
    match pg_inet::to_ipnet(cidr)? {
        ipnet::IpNet::V4(n) => Ok(n.prefix_len()),
        _ => Ok(24),
    }
}

async fn load_exit_nodes(pool: &PgPool, network_id: Uuid) -> anyhow::Result<Vec<ExitNodeInfo>> {
    let rows: Vec<(String, PgIp, Vec<PgIp>)> = sqlx::query_as(
        "SELECT e.endpoint_id, nm.assigned_ip::inet, e.allowed_cidrs \
         FROM exit_node_config e \
         JOIN network_memberships nm \
           ON nm.endpoint_id = e.endpoint_id AND nm.network_id = e.network_id \
         WHERE e.network_id = $1 AND e.enabled = true AND nm.status = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    let mut nodes = Vec::with_capacity(rows.len());
    for (endpoint_id, assigned_ip, allowed) in rows {
        let via_ip = match pg_inet::to_ipv4_addr(assigned_ip) {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let mut allowed_cidrs = Vec::new();
        for c in allowed {
            if let Ok(ipnet::IpNet::V4(n)) = pg_inet::to_ipnet(c) {
                allowed_cidrs.push(n);
            }
        }
        if allowed_cidrs.is_empty() {
            allowed_cidrs.push("0.0.0.0/0".parse()?);
        }
        nodes.push(ExitNodeInfo {
            endpoint_id,
            via_ip,
            allowed_cidrs,
        });
    }
    Ok(nodes)
}

async fn load_device_profile(
    pool: &PgPool,
    endpoint_id: &str,
    network_id: Uuid,
) -> anyhow::Result<DeviceProfile> {
    let row: Option<(Option<String>, String, Vec<PgIp>)> = sqlx::query_as(
        "SELECT exit_node_endpoint_id, split_tunnel_mode, split_tunnel_cidrs \
         FROM device_profiles \
         WHERE endpoint_id = $1 AND network_id = $2",
    )
    .bind(endpoint_id)
    .bind(network_id)
    .fetch_optional(pool)
    .await?;

    let Some((exit_node, mode, cidrs)) = row else {
        return Ok(DeviceProfile::default());
    };

    let split_tunnel_mode = match mode.as_str() {
        "include" => SplitTunnelMode::Include,
        _ => SplitTunnelMode::Exclude,
    };
    let mut split_tunnel_cidrs = Vec::new();
    for c in cidrs {
        if let Ok(ipnet::IpNet::V4(n)) = pg_inet::to_ipnet(c) {
            split_tunnel_cidrs.push(n);
        }
    }

    Ok(DeviceProfile {
        exit_node_endpoint_id: exit_node,
        split_tunnel_mode,
        split_tunnel_cidrs,
    })
}

async fn load_hostname_routes(
    pool: &PgPool,
    network_id: Uuid,
) -> anyhow::Result<Vec<HostnameRoute>> {
    let rows: Vec<(String, String, bool, Option<PgIp>, PgIp)> = sqlx::query_as(
        "SELECT COALESCE(ng.active_endpoint_id, hr.endpoint_id) AS via_endpoint_id, \
                hr.hostname, hr.is_wildcard, hr.target_ip, nm.assigned_ip::inet \
         FROM hostname_routes hr \
         LEFT JOIN node_group_members ngm ON ngm.endpoint_id = hr.endpoint_id \
         LEFT JOIN node_groups ng \
           ON ng.id = ngm.group_id AND ng.ha_enabled AND ng.network_id = hr.network_id \
         JOIN network_memberships nm \
           ON nm.endpoint_id = COALESCE(ng.active_endpoint_id, hr.endpoint_id) \
          AND nm.network_id = hr.network_id \
         WHERE hr.network_id = $1 AND hr.enabled = true AND nm.status = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    let mut routes = Vec::with_capacity(rows.len());
    for (via_endpoint_id, hostname, is_wildcard, target_ip, assigned_ip) in rows {
        let via_ip = match pg_inet::to_ipv4_addr(assigned_ip) {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let target_ip = match target_ip {
            Some(ip) => match pg_inet::to_ipv4_addr(ip) {
                Ok(v) => Some(v),
                Err(_) => continue,
            },
            None => None,
        };
        routes.push(HostnameRoute {
            hostname,
            via_endpoint_id,
            via_ip,
            is_wildcard,
            target_ip,
        });
    }
    Ok(routes)
}

async fn load_subnet_routes(pool: &PgPool, network_id: Uuid) -> anyhow::Result<Vec<SubnetRoute>> {
    // When the advertising machine is in an HA group, peers see the active member as via.
    let rows: Vec<(String, PgIp, PgIp)> = sqlx::query_as(
        "SELECT COALESCE(ng.active_endpoint_id, sr.endpoint_id) AS via_endpoint_id, \
                sr.cidr, nm.assigned_ip::inet \
         FROM subnet_routes sr \
         LEFT JOIN node_group_members ngm ON ngm.endpoint_id = sr.endpoint_id \
         LEFT JOIN node_groups ng \
           ON ng.id = ngm.group_id AND ng.ha_enabled AND ng.network_id = sr.network_id \
         JOIN network_memberships nm \
           ON nm.endpoint_id = COALESCE(ng.active_endpoint_id, sr.endpoint_id) \
          AND nm.network_id = sr.network_id \
         WHERE sr.network_id = $1 AND sr.enabled = true AND nm.status = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;

    let mut routes = Vec::with_capacity(rows.len());
    for (via_endpoint_id, cidr, assigned_ip) in rows {
        let ipnet::IpNet::V4(cidr) = pg_inet::to_ipnet(cidr)? else {
            continue;
        };
        let via_ip = match pg_inet::to_ipv4_addr(assigned_ip) {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        routes.push(SubnetRoute {
            cidr,
            via_endpoint_id,
            via_ip,
        });
    }
    Ok(routes)
}

async fn load_ipv4_peers(
    pool: &PgPool,
    network_id: Uuid,
    self_endpoint_id: &str,
    _network_name: &str,
) -> anyhow::Result<Vec<PeerEntry>> {
    let peer_rows: Vec<(String, String, PgIp)> = sqlx::query_as(
        "SELECT e.endpoint_id, \
            COALESCE(NULLIF(e.metadata->>'hostname', ''), left(e.endpoint_id, 8)) AS hostname, \
            nm.assigned_ip::inet \
         FROM network_memberships nm \
         JOIN devices e ON e.endpoint_id = nm.endpoint_id \
         WHERE nm.network_id = $1 AND nm.status = 'active' AND nm.endpoint_id <> $2 \
           AND nm.last_seen > now() - interval '5 minutes'",
    )
    .bind(network_id)
    .bind(self_endpoint_id)
    .fetch_all(pool)
    .await?;

    let mut peers = Vec::with_capacity(peer_rows.len());
    for (eid, host, assigned_ip) in peer_rows {
        let ip = match pg_inet::to_ipv4_addr(assigned_ip) {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let tag_rows: Vec<(String,)> =
            sqlx::query_as("SELECT tag FROM device_tags WHERE endpoint_id = $1")
                .bind(&eid)
                .fetch_all(pool)
                .await?;
        peers.push(PeerEntry {
            ip,
            endpoint_id: eid,
            hostname: host,
            tags: tag_rows.into_iter().map(|(t,)| t).collect(),
        });
    }
    Ok(peers)
}

async fn load_ipv6_peers(
    pool: &PgPool,
    organization_id: &str,
    self_endpoint_id: &str,
) -> anyhow::Result<Vec<Ipv6PeerEntry>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT endpoint_id, \
            COALESCE(NULLIF(metadata->>'hostname', ''), left(endpoint_id, 8)) AS hostname \
         FROM devices \
         WHERE organization_id = $1 AND ipv6_enabled AND endpoint_id <> $2",
    )
    .bind(organization_id)
    .bind(self_endpoint_id)
    .fetch_all(pool)
    .await?;

    let mut peers = Vec::with_capacity(rows.len());
    for (eid, host) in rows {
        let ip = tuntun_common::ipv6::derive_tenant_ipv6(&eid)?;
        let tag_rows: Vec<(String,)> =
            sqlx::query_as("SELECT tag FROM device_tags WHERE endpoint_id = $1")
                .bind(&eid)
                .fetch_all(pool)
                .await?;
        peers.push(Ipv6PeerEntry {
            ip,
            endpoint_id: eid,
            hostname: host,
            tags: tag_rows.into_iter().map(|(t,)| t).collect(),
        });
    }
    Ok(peers)
}

async fn load_device_tags(pool: &PgPool, endpoint_id: &str) -> anyhow::Result<Vec<String>> {
    let tag_rows: Vec<(String,)> =
        sqlx::query_as("SELECT tag FROM device_tags WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_all(pool)
            .await?;
    Ok(tag_rows.into_iter().map(|(t,)| t).collect())
}
