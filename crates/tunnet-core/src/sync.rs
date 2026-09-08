use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use parking_lot::Mutex;
use tunnet_common::policy::{PolicyBundle, merge_policy_bundles, verify_policy_bundle_signature};
use tunnet_common::ws::{ClientMsg, ServerMsg};
use tunnet_common::{EndpointSnapshot, NetworkMembershipSnapshot};
use uuid::Uuid;

use crate::acl::AclEngine;
use crate::control::SignedClient;
use crate::routing::RoutingTable;
use crate::state::{StatePaths, save_snapshot_cache};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgRevision(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRevision(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedRevisionSnapshot {
    pub org: OrgRevision,
    pub network: NetworkRevision,
}

#[derive(Debug)]
pub struct ManagedRevisions {
    applied: Mutex<ManagedRevisionSnapshot>,
}

impl ManagedRevisions {
    pub fn new(org: u64, network: u64) -> Self {
        Self {
            applied: Mutex::new(ManagedRevisionSnapshot {
                org: OrgRevision(org),
                network: NetworkRevision(network),
            }),
        }
    }

    pub fn load(&self) -> ManagedRevisionSnapshot {
        *self.applied.lock()
    }

    pub fn accept_absence(&self, org: u64, network: u64) -> bool {
        let mut current = self.applied.lock();
        if org < current.org.0 || network < current.network.0 {
            return false;
        }
        current.org = OrgRevision(org);
        current.network = NetworkRevision(network);
        true
    }

    fn apply_snapshot(
        &self,
        org: OrgRevision,
        network: NetworkRevision,
        apply: impl FnOnce(),
    ) -> bool {
        let mut current = self.applied.lock();
        if org.0 < current.org.0 || network.0 < current.network.0 {
            return false;
        }
        apply();
        *current = ManagedRevisionSnapshot { org, network };
        true
    }

    fn apply_delta(&self, network: NetworkRevision, apply: impl FnOnce()) -> bool {
        let mut current = self.applied.lock();
        if network.0 < current.network.0 {
            return false;
        }
        apply();
        current.network = network;
        true
    }
}

pub fn membership_for_network(
    snap: &EndpointSnapshot,
    network_id: Uuid,
) -> anyhow::Result<&NetworkMembershipSnapshot> {
    snap.memberships
        .iter()
        .find(|m| m.network_id == network_id)
        .with_context(|| format!("network {network_id} not in snapshot"))
}

fn parse_policy_vk(hex_key: Option<&str>) -> Option<VerifyingKey> {
    let hex = hex_key?;
    let bytes = hex::decode(hex).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Verify org + network bundle signatures, then merge into the effective ACL.
/// On bad signature: keep last-good routes and ACL (do not replace).
#[allow(clippy::too_many_arguments)]
pub fn apply_membership(
    membership: &NetworkMembershipSnapshot,
    org_policy: &PolicyBundle,
    policy_verifying_key: Option<&str>,
    routes: &RoutingTable,
    acl: &AclEngine,
    revisions: &Arc<ManagedRevisions>,
    org_version: u64,
    self_endpoint_id: &str,
    self_hostname: &str,
    known_hosts_dir: Option<&std::path::Path>,
) -> bool {
    // Verify policy signatures BEFORE mutating routes/ACL.
    if let Some(vk) = parse_policy_vk(policy_verifying_key) {
        if let Err(e) = verify_policy_bundle_signature(&membership.policy, &vk) {
            tracing::warn!(
                ?e,
                "network policy signature invalid; keeping previous routes+ACL"
            );
            return false;
        }
        if let Err(e) = verify_policy_bundle_signature(org_policy, &vk) {
            tracing::warn!(
                ?e,
                "org policy signature invalid; keeping previous routes+ACL"
            );
            return false;
        }
    } else if !membership.policy.signature.is_empty() || !org_policy.signature.is_empty() {
        tracing::debug!(
            "policy verifying key missing; applying merged policy without signature check"
        );
    }

    // Control plane excludes this endpoint from ipv4_peers (no mesh self-route).
    // Inject self so PeerDNS can resolve our own hostname → assigned mesh IP.
    let hostname = if !membership.self_hostname.is_empty() {
        membership.self_hostname.as_str()
    } else {
        self_hostname
    };
    let mut peers = Vec::with_capacity(membership.ipv4_peers.len() + 1);
    peers.extend_from_slice(&membership.ipv4_peers);
    if !hostname.is_empty() && !peers.iter().any(|p| p.endpoint_id == self_endpoint_id) {
        peers.push(tunnet_common::PeerEntry {
            ip: membership.assigned_ipv4,
            endpoint_id: self_endpoint_id.to_string(),
            hostname: hostname.to_string(),
            tags: membership.self_tags.clone(),
            ssh_host_key: None,
        });
    }

    let merged = merge_policy_bundles(org_policy, &membership.policy);
    let applied = revisions.apply_snapshot(
        OrgRevision(org_version),
        NetworkRevision(membership.version),
        || {
            routes.replace(
                &peers,
                &membership.subnet_routes,
                &membership.hostname_routes,
                &membership.exit_nodes,
                &membership.device_profile,
                &membership.dns,
                &membership.network_name,
                membership.network_id,
                self_endpoint_id,
                membership.version,
            );
            acl.replace_bundle(merged);
            acl.replace_self_tags(membership.self_tags.clone());
        },
    );
    if !applied {
        return false;
    }

    if let Some(dir) = known_hosts_dir
        && let Err(e) = crate::known_hosts::sync_known_hosts(dir, &peers, &membership.dns.suffix)
    {
        tracing::debug!(?e, "known_hosts sync skipped");
    }
    true
}

/// Apply a peer-only SnapshotDelta (no policy / route table replace).
pub fn apply_delta(
    routes: &RoutingTable,
    revisions: &Arc<ManagedRevisions>,
    delta: &tunnet_common::SnapshotDelta,
    self_endpoint_id: &str,
    network_id: Uuid,
    network_name: &str,
) -> bool {
    revisions.apply_delta(NetworkRevision(delta.version), || {
        routes.apply_peer_delta(
            network_id,
            &delta.added,
            &delta.removed,
            delta.version,
            self_endpoint_id,
            network_name,
        );
    })
}

/// Explicit owner-spawned managed control driver (no hidden tasks).
///
/// Runs the [`PendingControl`] transport plus snapshot/serve/tunnel/send
/// handling. Returns the [`JoinHandle`] so the caller owns lifecycle.
/// Agent daemons use `ControlPlaneActor` instead; SDK/kube-node use this.
pub struct ManagedDriverCtx {
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub revisions: Arc<ManagedRevisions>,
    pub paths: StatePaths,
    pub network_id: Uuid,
    pub self_endpoint_id: String,
    pub self_hostname: String,
    pub agent_version: &'static str,
    /// Periodic snapshot poll interval (fallback when WS stalls).
    pub poll_secs: u64,
    pub poll_client: Option<SignedClient>,
    #[cfg(feature = "serve")]
    pub serves: Option<crate::serve::ServeManager>,
    #[cfg(feature = "tunnel")]
    pub tunnels: Option<crate::tunnel::TunnelManager>,
    #[cfg(feature = "send")]
    pub send: Option<crate::send::SendManager>,
    pub tunnel_pool: Option<crate::iroh_pool::ConnPool>,
    pub pool: Option<crate::iroh_pool::ConnPool>,
    pub effective_config: Option<crate::EffectiveConfigStore>,
}

impl ManagedDriverCtx {
    /// Build from a bootstrapped node. Serve/tunnel/send managers are wired
    /// according to this crate's enabled features.
    pub fn from_node(
        node: &crate::node::CoreNode,
        network_id: Uuid,
        self_hostname: String,
        agent_version: &'static str,
        poll_secs: u64,
    ) -> Self {
        Self {
            routes: node.routes.clone(),
            acl: node.acl.clone(),
            revisions: node.revisions.clone(),
            paths: node.paths.clone(),
            network_id,
            self_endpoint_id: node.endpoint_id_hex(),
            self_hostname,
            agent_version,
            poll_secs,
            poll_client: node.signed.clone(),
            #[cfg(feature = "serve")]
            serves: Some(node.serves.clone()),
            #[cfg(feature = "tunnel")]
            tunnels: Some(node.tunnels.clone()),
            #[cfg(feature = "send")]
            send: Some(node.send.clone()),
            tunnel_pool: Some(node.tunnel_pool.clone()),
            pool: Some(node.pool.clone()),
            effective_config: Some(node.effective_config.clone()),
        }
    }
}

pub fn spawn_managed_driver(
    pending: crate::ws_client::PendingControl,
    ctx: ManagedDriverCtx,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let ManagedDriverCtx {
            routes,
            acl,
            revisions,
            paths,
            network_id,
            self_endpoint_id,
            self_hostname,
            agent_version,
            poll_secs,
            poll_client,
            #[cfg(feature = "serve")]
            serves,
            #[cfg(feature = "tunnel")]
            tunnels,
            #[cfg(feature = "send")]
            send,
            tunnel_pool,
            pool,
            effective_config,
        } = ctx;
        let crate::ws_client::PendingControl {
            transport,
            server_tx,
            mut server_rx,
            client_tx,
            client_rx,
        } = pending;
        // Owned transport task; cancelled when the driver ends.
        let transport_cancel = tokio_util::sync::CancellationToken::new();
        let transport_task = {
            let cancel = transport_cancel.clone();
            tokio::spawn(async move {
                transport.run(server_tx, client_rx, cancel).await;
            })
        };
        let _ = client_tx
            .send(ClientMsg::Hello {
                endpoint_id: "self".into(),
                agent_version: agent_version.into(),
                known_version: revisions.load().org.0,
            })
            .await;
        let pools: Vec<crate::iroh_pool::ConnPool> =
            pool.into_iter().chain(tunnel_pool.clone()).collect();

        let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Don't fire immediately; WS connect already slides last_heartbeat_at.
        heartbeat.tick().await;
        // Owned poll fallback (same task, no hidden detached timer).
        let mut poll_ticker = tokio::time::interval(Duration::from_secs(poll_secs.max(5)));
        poll_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        poll_ticker.tick().await;
        loop {
            tokio::select! {
                _ = poll_ticker.tick() => {
                    if let Some(client) = &poll_client {
                        poll_once(
                            client,
                            &revisions,
                            &routes,
                            &acl,
                            network_id,
                            &self_endpoint_id,
                            &self_hostname,
                            Some(paths.dir.as_path()),
                            &pools,
                        )
                        .await;
                    }
                }
                Some(msg) = server_rx.recv() => {
                    match msg {
                        ServerMsg::Snapshot(snap) => {
                            if let Ok(m) = membership_for_network(&snap, network_id) {
                                if !apply_membership(
                                    m,
                                    &snap.org_policy,
                                    snap.policy_verifying_key.as_deref(),
                                    &routes,
                                    &acl,
                                    &revisions,
                                    snap.version,
                                    &self_endpoint_id,
                                    &self_hostname,
                                    Some(paths.dir.as_path()),
                                ) {
                                    continue;
                                }
                                if let Some(pool) = tunnel_pool.as_ref() {
                                    pool.set_cloud_relay_urls(
                                        snap.connectivity_relays
                                            .iter()
                                            .filter(|r| r.metering)
                                            .map(|r| r.url.clone()),
                                    );
                                }
                                for p in &pools {
                                    p.reconcile().await;
                                }
                                save_snapshot_cache(&paths, &snap).ok();
                                tracing::info!(
                                    v = m.version,
                                    peers = m.ipv4_peers.len(),
                                    subnet_routes = m.subnet_routes.len(),
                                    hostname_routes = m.hostname_routes.len(),
                                    "snapshot from ws"
                                );
                                // Merge remote policy into the effective config
                                // directly (no callback hooks) and report it.
                                if let Some(store) = &effective_config {
                                    let local = crate::TunnetConfig::try_load(&paths)
                                        .ok()
                                        .flatten()
                                        .unwrap_or_default();
                                    let config =
                                        store.apply_remote(&local, m.agent_policy.clone());
                                    let _ = client_tx
                                        .send(ClientMsg::EffectiveConfigReport {
                                            config,
                                            reported_at: jiff::Timestamp::now(),
                                        })
                                        .await;
                                }
                            } else if snap
                                .network_revisions
                                .get(&network_id)
                                .is_some_and(|network| revisions.accept_absence(snap.version, *network))
                            {
                                routes.clear_managed(network_id, &self_endpoint_id);
                                for p in &pools {
                                    p.reconcile().await;
                                    p.close_all().await;
                                }
                                save_snapshot_cache(&paths, &snap).ok();
                                if let Some(store) = &effective_config {
                                let local = crate::TunnetConfig::try_load(&paths)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();
                                let config =
                                    store.apply_remote(&local, snap.agent_policy.clone());
                                let _ = client_tx
                                    .send(ClientMsg::EffectiveConfigReport {
                                        config,
                                        reported_at: jiff::Timestamp::now(),
                                    })
                                    .await;
                                }
                            }
                        }
                        ServerMsg::Delta(delta) => {
                            tracing::info!(
                                v = delta.version,
                                added = delta.added.len(),
                                removed = delta.removed.len(),
                                "delta received"
                            );
                            let network_name = routes.network_name();
                            if !apply_delta(
                                &routes,
                            &revisions,
                                &delta,
                                &self_endpoint_id,
                                network_id,
                                &network_name,
                            ) {
                                continue;
                            }
                            for p in &pools {
                                p.reconcile().await;
                            }
                        }
                        ServerMsg::MembershipRevoked {
                            network_id: revoked_network_id,
                            org_revision,
                            network_revision,
                            reason,
                        } => {
                            if revoked_network_id == network_id
                                && revisions.accept_absence(org_revision, network_revision)
                            {
                                routes.clear_managed(network_id, &self_endpoint_id);
                                for pool in &pools {
                                    pool.reconcile().await;
                                    pool.close_all().await;
                                }
                                tracing::warn!(%network_id, %reason, "managed membership revoked");
                            }
                        }
                        ServerMsg::ForceReenroll { reason } => {
                            tracing::error!(%reason, "control plane requested re-enrollment");
                            break;
                        }
                        ServerMsg::Ping { nonce } => {
                            let _ = client_tx.send(ClientMsg::Pong { nonce }).await;
                            if let Some(client) = &poll_client {
                                match client.poll(revisions.load().org.0).await {
                                    Ok(snap) => {
                                        if let Ok(m) = membership_for_network(&snap, network_id)
                                            && (snap.version != revisions.load().org.0
                                                || m.version != revisions.load().network.0)
                                        {
                                            if !apply_membership(
                                                m,
                                                &snap.org_policy,
                                                snap.policy_verifying_key.as_deref(),
                                                &routes,
                                                &acl,
                                                &revisions,
                                                snap.version,
                                                &self_endpoint_id,
                                                &self_hostname,
                                                Some(paths.dir.as_path()),
                                            ) {
                                                continue;
                                            }
                                            for p in &pools {
                                                p.reconcile().await;
                                            }
                                            save_snapshot_cache(&paths, &snap).ok();
                                            tracing::info!(
                                                v = m.version,
                                                "snapshot from ping wake-up poll"
                                            );
                                            if let Some(store) = &effective_config {
                                                let local = crate::TunnetConfig::try_load(&paths)
                                                    .ok()
                                                    .flatten()
                                                    .unwrap_or_default();
                                                let config = store.apply_remote(
                                                    &local,
                                                    m.agent_policy.clone(),
                                                );
                                                let _ = client_tx
                                                    .send(ClientMsg::EffectiveConfigReport {
                                                        config,
                                                        reported_at: jiff::Timestamp::now(),
                                                    })
                                                    .await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(?e, "ping wake-up poll failed");
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "serve")]
                        ServerMsg::StartServe {
                            serve_id,
                            port,
                            protocol,
                            internal_hostname,
                            certificate_pem,
                            private_key_pem,
                            access_mode,
                            allowed_tags,
                            allowed_endpoint_ids,
                            target_addr,
                        } => {
                            let parsed_target = target_addr.as_deref().and_then(|s| {
                                s.parse::<std::net::SocketAddr>().map_err(|e| {
                                    tracing::warn!(?e, target = %s, "invalid StartServe target_addr");
                                    e
                                }).ok()
                            });
                            let result = if let Some(mgr) = &serves {
                                mgr.start(
                                    serve_id.clone(),
                                    port,
                                    &protocol,
                                    &internal_hostname,
                                    certificate_pem.as_deref(),
                                    private_key_pem.as_deref(),
                                    crate::serve::ServeAcl {
                                        access_mode,
                                        allowed_tags,
                                        allowed_endpoint_ids,
                                    },
                                    parsed_target,
                                    true,
                                )
                                .await
                            } else {
                                Err(anyhow::anyhow!("serve manager not available"))
                            };
                            match result {
                                Ok(_) => {
                                    let _ = client_tx.send(ClientMsg::ServeReady { serve_id }).await;
                                }
                                Err(e) => {
                                    tracing::warn!(?e, %serve_id, "StartServe failed");
                                    let _ = client_tx
                                        .send(ClientMsg::ServeFailed {
                                            serve_id,
                                            error: e.to_string(),
                                        })
                                        .await;
                                }
                            }
                        }
                        #[cfg(not(feature = "serve"))]
                        ServerMsg::StartServe { serve_id, .. } => {
                            tracing::warn!(%serve_id, "StartServe ignored (`serve` feature disabled)");
                            let _ = client_tx
                                .send(ClientMsg::ServeFailed {
                                    serve_id,
                                    error: "serve feature disabled".into(),
                                })
                                .await;
                        }
                        #[cfg(feature = "serve")]
                        ServerMsg::ReconcileServes { serve_ids } => {
                            if let Some(mgr) = &serves {
                                mgr.reconcile_managed(&serve_ids).await;
                            }
                        }
                        #[cfg(not(feature = "serve"))]
                        ServerMsg::ReconcileServes { .. } => {
                            tracing::warn!("ReconcileServes ignored (`serve` feature disabled)");
                        }
                        #[cfg(feature = "serve")]
                        ServerMsg::StopServe { serve_id } => {
                            if let Some(mgr) = &serves {
                                match mgr.stop_by_id(&serve_id).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        tracing::debug!(
                                            ?e,
                                            %serve_id,
                                            "StopServe: serve not active (already stopped?)"
                                        );
                                    }
                                }
                            }
                            let _ = client_tx.send(ClientMsg::ServeStopped { serve_id }).await;
                        }
                        #[cfg(not(feature = "serve"))]
                        ServerMsg::StopServe { serve_id } => {
                            tracing::warn!(%serve_id, "StopServe ignored (`serve` feature disabled)");
                            let _ = client_tx.send(ClientMsg::ServeStopped { serve_id }).await;
                        }
                        #[cfg(feature = "tunnel")]
                        ServerMsg::OpenTunnel {
                            tunnel_id,
                            edge_addr,
                            subdomain,
                            public_hostname,
                            local_port,
                            protocol,
                            auth_token,
                            redirect_rules,
                            target_addr,
                        } => {
                            let parsed_target = target_addr.as_deref().and_then(|s| {
                                s.parse::<std::net::SocketAddr>().map_err(|e| {
                                    tracing::warn!(?e, target = %s, "invalid OpenTunnel target_addr");
                                    e
                                }).ok()
                            });
                            let result = if let Some(mgr) = &tunnels {
                                mgr.start(
                                    tunnel_id.clone(),
                                    &edge_addr,
                                    &subdomain,
                                    &public_hostname,
                                    local_port,
                                    &protocol,
                                    &auth_token,
                                    redirect_rules,
                                    parsed_target,
                                    false,
                                    None,
                                )
                                .await
                            } else {
                                Err(anyhow::anyhow!("tunnel manager not available"))
                            };
                            match result {
                                Ok(info) => {
                                    tracing::info!(url = %info.public_url, "OpenTunnel active");
                                    let _ = client_tx.send(ClientMsg::TunnelReady { tunnel_id }).await;
                                }
                                Err(e) => {
                                    tracing::warn!(?e, %tunnel_id, "OpenTunnel failed");
                                    let _ = client_tx
                                        .send(ClientMsg::TunnelFailed {
                                            tunnel_id,
                                            error: e.to_string(),
                                        })
                                        .await;
                                }
                            }
                        }
                        #[cfg(not(feature = "tunnel"))]
                        ServerMsg::OpenTunnel { tunnel_id, .. } => {
                            tracing::warn!(%tunnel_id, "OpenTunnel ignored (`tunnel` feature disabled)");
                            let _ = client_tx
                                .send(ClientMsg::TunnelFailed {
                                    tunnel_id,
                                    error: "tunnel feature disabled".into(),
                                })
                                .await;
                        }
                        #[cfg(feature = "tunnel")]
                        ServerMsg::StopTunnel { tunnel_id } => {
                            if let Some(mgr) = &tunnels {
                                let _ = mgr.stop(&tunnel_id);
                            }
                            let _ = client_tx.send(ClientMsg::TunnelStopped { tunnel_id }).await;
                        }
                        #[cfg(not(feature = "tunnel"))]
                        ServerMsg::StopTunnel { tunnel_id } => {
                            tracing::warn!(%tunnel_id, "StopTunnel ignored (`tunnel` feature disabled)");
                            let _ = client_tx.send(ClientMsg::TunnelStopped { tunnel_id }).await;
                        }
                        ServerMsg::KillSshSession { session_id } => {
                            // No posture/SSH engine in the core driver;
                            // the agent actor handles kills via SshRegistryActor.
                            tracing::warn!(%session_id, "KillSshSession ignored (core driver has no session registry)");
                        }
                        #[cfg(feature = "send")]
                        ServerMsg::SendFile {
                            transfer_id,
                            path,
                            target,
                            message,
                        } => {
                            if let Some(mgr) = &send {
                                let path = std::path::PathBuf::from(path);
                                match mgr
                                    .send_file_with_id(
                                        &path,
                                        &target,
                                        message,
                                        Some(transfer_id.clone()),
                                    )
                                    .await
                                {
                                    Ok(_) => {
                                        tracing::info!(%transfer_id, "SendFile started");
                                    }
                                    Err(e) => {
                                        tracing::warn!(?e, %transfer_id, "SendFile failed");
                                        let _ = client_tx
                                            .send(ClientMsg::TransferFailed {
                                                transfer_id,
                                                error: e.to_string(),
                                                rejected: false,
                                            })
                                            .await;
                                    }
                                }
                            }
                        }
                        #[cfg(not(feature = "send"))]
                        ServerMsg::SendFile { transfer_id, .. } => {
                            tracing::warn!(%transfer_id, "SendFile ignored (`send` feature disabled)");
                            let _ = client_tx
                                .send(ClientMsg::TransferFailed {
                                    transfer_id,
                                    error: "send feature disabled".into(),
                                    rejected: false,
                                })
                                .await;
                        }
                        #[cfg(feature = "send")]
                        ServerMsg::AcceptTransfer { transfer_id } => {
                            if let Some(mgr) = &send
                                && let Err(e) = mgr.accept_pending(&transfer_id).await
                            {
                                tracing::warn!(?e, %transfer_id, "AcceptTransfer failed");
                            }
                        }
                        #[cfg(not(feature = "send"))]
                        ServerMsg::AcceptTransfer { transfer_id } => {
                            tracing::warn!(%transfer_id, "AcceptTransfer ignored (`send` feature disabled)");
                        }
                        #[cfg(feature = "send")]
                        ServerMsg::RejectTransfer {
                            transfer_id,
                            reason,
                        } => {
                            if let Some(mgr) = &send
                                && let Err(e) = mgr.reject_pending(&transfer_id, reason).await
                            {
                                tracing::warn!(?e, %transfer_id, "RejectTransfer failed");
                            }
                        }
                        #[cfg(not(feature = "send"))]
                        ServerMsg::RejectTransfer { transfer_id, .. } => {
                            tracing::warn!(%transfer_id, "RejectTransfer ignored (`send` feature disabled)");
                        }
                        #[cfg(feature = "send")]
                        ServerMsg::SetSendConsent {
                            mode,
                            inbox_path,
                            pin_blobs,
                        } => {
                            if let Some(mgr) = &send {
                                let mut cfg = mgr.config();
                                if let Some(m) =
                                    tunnet_common::send::SendConsentMode::parse(&mode)
                                {
                                    cfg.consent = m;
                                }
                                if let Some(p) = inbox_path {
                                    cfg.inbox_path = std::path::PathBuf::from(p);
                                }
                                cfg.pin_blobs = pin_blobs;
                                mgr.set_config(cfg);
                                tracing::info!(%mode, "SetSendConsent applied");
                            }
                        }
                        #[cfg(not(feature = "send"))]
                        ServerMsg::SetSendConsent { mode, .. } => {
                            tracing::warn!(%mode, "SetSendConsent ignored (`send` feature disabled)");
                        }
                        ServerMsg::PostureRecheck => {
                            tracing::debug!("PostureRecheck ignored (core driver has no posture engine)");
                        }
                        ServerMsg::PostureConfigUpdate { interval_secs, .. } => {
                            tracing::debug!(interval_secs, "PostureConfigUpdate ignored (core driver has no posture engine)");
                        }
                        ServerMsg::AgentConfigUpdate { policy } => {
                            if let Some(store) = &effective_config {
                                let local = crate::TunnetConfig::try_load(&paths)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();
                                let config = store.apply_remote(&local, policy);
                                let _ = client_tx
                                    .send(ClientMsg::EffectiveConfigReport {
                                        config,
                                        reported_at: jiff::Timestamp::now(),
                                    })
                                    .await;
                                tracing::info!("AgentConfigUpdate applied");
                            }
                        }
                        ServerMsg::PostureStatus { enforcement_action, .. } => {
                            tracing::debug!(%enforcement_action, "PostureStatus ignored (core driver has no posture engine)");
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let (active_conns, bytes_tx, bytes_rx) = tunnel_pool
                        .as_ref()
                        .map(|p| p.heartbeat_counters())
                        .unwrap_or((0, 0, 0));
                    let _ = client_tx.send(ClientMsg::Heartbeat {
                        active_conns,
                        bytes_tx,
                        bytes_rx,
                    }).await;
                    if let Some(pool) = tunnel_pool.as_ref() {
                        let bytes = pool.cloud_relay_meter().take();
                        if bytes > 0 {
                            let _ = client_tx.send(ClientMsg::CloudRelayUsage { bytes }).await;
                        }
                    }
                }
            }
        }
        transport_cancel.cancel();
        let _ = transport_task.await;
    })
}

/// One snapshot poll + apply. Shared by the core driver loop and the agent
/// `ControlPlaneActor`; both run it as owned periodic work (never a hidden
/// detached task).
///
/// Overlapping polls can complete out of order: a provably older snapshot
/// (strictly lower version than already applied) is skipped. Equal versions
/// still re-apply — peer lists / keys can change without a version bump.
#[allow(clippy::too_many_arguments)]
pub async fn poll_once(
    client: &SignedClient,
    revisions: &Arc<ManagedRevisions>,
    routes: &RoutingTable,
    acl: &AclEngine,
    network_id: Uuid,
    self_endpoint_id: &str,
    self_hostname: &str,
    known_hosts_dir: Option<&std::path::Path>,
    pools: &[crate::iroh_pool::ConnPool],
) {
    match client.poll(revisions.load().org.0).await {
        Ok(snap) => {
            if let Ok(m) = membership_for_network(&snap, network_id) {
                if !apply_membership(
                    m,
                    &snap.org_policy,
                    snap.policy_verifying_key.as_deref(),
                    routes,
                    acl,
                    revisions,
                    snap.version,
                    self_endpoint_id,
                    self_hostname,
                    known_hosts_dir,
                ) {
                    tracing::debug!(
                        org = snap.version,
                        network = m.version,
                        current_org = revisions.load().org.0,
                        current_network = revisions.load().network.0,
                        "ignoring stale poll snapshot"
                    );
                    return;
                }
                for p in pools {
                    p.reconcile().await;
                }
                tracing::info!(
                    v = m.version,
                    peers = m.ipv4_peers.len(),
                    subnet_routes = m.subnet_routes.len(),
                    hostname_routes = m.hostname_routes.len(),
                    "snapshot via poll"
                );
            } else if snap
                .network_revisions
                .get(&network_id)
                .is_some_and(|network| revisions.accept_absence(snap.version, *network))
            {
                routes.clear_managed(network_id, self_endpoint_id);
                for pool in pools {
                    pool.reconcile().await;
                    pool.close_all().await;
                }
            }
        }
        Err(e) => {
            acl.mark_stale();
            tracing::warn!(?e, "poll failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tunnet_common::SnapshotDelta;

    fn membership(version: u64, policy: PolicyBundle) -> NetworkMembershipSnapshot {
        NetworkMembershipSnapshot {
            network_id: Uuid::nil(),
            network_name: "office".into(),
            assigned_ipv4: "10.7.0.1".parse().unwrap(),
            prefix: 24,
            mtu: 1280,
            ipv4_peers: vec![tunnet_common::PeerEntry {
                ip: "10.7.0.2".parse().unwrap(),
                endpoint_id: "b".repeat(64),
                hostname: "peer".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            subnet_routes: vec![],
            hostname_routes: vec![],
            dns: tunnet_common::DnsConfig::default(),
            exit_nodes: vec![],
            device_profile: tunnet_common::DeviceProfile::default(),
            active_serves: vec![],
            tunnel_config: vec![],
            self_tags: vec![],
            self_hostname: "self".into(),
            policy,
            gossip_bootstrap: vec![],
            gossip_topic_hex: String::new(),
            agent_policy: tunnet_common::RemoteAgentPolicy::default(),
            version,
        }
    }

    #[test]
    fn network_revision_never_overwrites_org_revision() {
        let revisions = ManagedRevisions::new(7, 100);
        assert!(revisions.apply_delta(NetworkRevision(101), || {}));
        assert_eq!(revisions.load().org, OrgRevision(7));
        assert_eq!(revisions.load().network, NetworkRevision(101));
        assert!(revisions.apply_snapshot(OrgRevision(8), NetworkRevision(102), || {}));
        assert_eq!(revisions.load().org, OrgRevision(8));
    }

    #[test]
    fn policy_create_update_delete_apply_without_restart() {
        use tunnet_common::policy::{DefaultAction, IcmpPolicy};

        let routes = RoutingTable::new();
        let self_id = "a".repeat(64);
        let acl = AclEngine::new(
            crate::acl::SelfIdentity {
                endpoint_hex: self_id.clone(),
                ip: "10.7.0.1".parse().unwrap(),
                tags: vec![],
                network: "office".into(),
            },
            routes.clone(),
            PolicyBundle::default(),
        );
        let revisions = Arc::new(ManagedRevisions::new(7, 100));
        for (network_revision, default_action) in [
            (101, DefaultAction::Deny),
            (102, DefaultAction::Allow),
            (103, DefaultAction::Allow),
        ] {
            let policy = PolicyBundle {
                version: network_revision,
                default_action,
                icmp_policy: IcmpPolicy::Allow,
                ..PolicyBundle::default()
            };
            assert!(apply_membership(
                &membership(network_revision, policy),
                &PolicyBundle::default(),
                None,
                &routes,
                &acl,
                &revisions,
                8,
                &self_id,
                "self",
                None,
            ));
            assert_eq!(acl.policy_version(), network_revision);
        }
        assert_eq!(revisions.load().org, OrgRevision(8));
        assert_eq!(revisions.load().network, NetworkRevision(103));
    }

    #[test]
    fn authoritative_membership_removal_revokes_transport_immediately() {
        let routes = RoutingTable::new();
        let self_id = "a".repeat(64);
        let peer = "b".repeat(64);
        let acl = AclEngine::new(
            crate::acl::SelfIdentity {
                endpoint_hex: self_id.clone(),
                ip: "10.7.0.1".parse().unwrap(),
                tags: vec![],
                network: "office".into(),
            },
            routes.clone(),
            PolicyBundle::default(),
        );
        let revisions = Arc::new(ManagedRevisions::new(1, 1));
        assert!(apply_membership(
            &membership(2, PolicyBundle::default()),
            &PolicyBundle::default(),
            None,
            &routes,
            &acl,
            &revisions,
            2,
            &self_id,
            "self",
            None,
        ));
        let auth = crate::transport_auth::TransportAuth::managed(&routes);
        assert!(auth.allows(&peer));
        assert!(revisions.accept_absence(3, 3));
        routes.clear_managed(Uuid::nil(), &self_id);
        assert!(!auth.allows(&peer));
    }

    #[test]
    fn stale_completion_cannot_mutate_live_state() {
        let revisions = ManagedRevisions::new(1, 1);
        let applied = std::sync::atomic::AtomicU64::new(0);
        assert!(
            revisions.apply_snapshot(OrgRevision(3), NetworkRevision(30), || {
                applied.store(30, std::sync::atomic::Ordering::SeqCst);
            })
        );
        assert!(
            !revisions.apply_snapshot(OrgRevision(2), NetworkRevision(20), || {
                applied.store(20, std::sync::atomic::Ordering::SeqCst);
            })
        );
        assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 30);
    }

    #[test]
    fn concurrent_out_of_order_results_remain_monotonic() {
        let revisions = Arc::new(ManagedRevisions::new(1, 1));
        let applied = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let newer = {
            let revisions = revisions.clone();
            let applied = applied.clone();
            std::thread::spawn(move || {
                revisions.apply_snapshot(OrgRevision(3), NetworkRevision(30), || {
                    applied.store(30, std::sync::atomic::Ordering::SeqCst);
                })
            })
        };
        assert!(newer.join().unwrap());
        let older = {
            let revisions = revisions.clone();
            let applied = applied.clone();
            std::thread::spawn(move || {
                revisions.apply_snapshot(OrgRevision(2), NetworkRevision(20), || {
                    applied.store(20, std::sync::atomic::Ordering::SeqCst);
                })
            })
        };
        assert!(!older.join().unwrap());
        assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 30);
    }

    #[test]
    fn apply_delta_bumps_version() {
        let routes = RoutingTable::new();
        let self_id = "a".repeat(64);
        let peer_a = "b".repeat(64);
        let nid = Uuid::nil();
        routes.replace(
            &[],
            &[],
            &[],
            &[],
            &tunnet_common::DeviceProfile::default(),
            &tunnet_common::DnsConfig::default(),
            "office",
            nid,
            &self_id,
            1,
        );
        let revisions = Arc::new(ManagedRevisions::new(1, 1));
        let delta = SnapshotDelta {
            added: vec![tunnet_common::PeerEntry {
                ip: "10.7.0.5".parse().unwrap(),
                endpoint_id: peer_a.clone(),
                hostname: "alice".into(),
                tags: vec![],
                ssh_host_key: None,
            }],
            removed: vec![],
            version: 42,
        };
        apply_delta(&routes, &revisions, &delta, &self_id, nid, "office");
        assert_eq!(revisions.load().org, OrgRevision(1));
        assert_eq!(revisions.load().network, NetworkRevision(42));
        assert_eq!(routes.version(), 42);
        assert!(routes.lookup_endpoint(&peer_a).is_some());
    }
}
