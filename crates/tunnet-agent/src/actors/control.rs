//! `ControlPlaneActor`: owns managed control-plane transport lifecycle.
//!
//! The raw WebSocket transport (`ControlTransport` in `tunnet-core`) stays
//! Kameo-free. This actor owns its lifecycle, receives `ServerMsg`, applies
//! control state, and dispatches typed commands to subsystem actors.
//! Normal disconnects are operational state (reconnect/backoff), never actor
//! failures. Long independent I/O is delegated to subsystem managers via
//! bounded one-shot tasks so heartbeats/policy updates never stall.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use tunnet_common::ws::{ClientMsg, ServerMsg};
use tunnet_core::ws_client::{ControlPlaneLink, ControlTransport};
use tunnet_core::{CoreNode, StatePaths};
use uuid::Uuid;

use super::posture::{
    ApplyPostureConfig, ApplyRemoteAgentPolicy, PostureActor, PostureStatusChanged, Recheck,
};
use super::routes::{ApplyDesiredRoutes, RouteActor};
use super::ssh_registry::SshRegistryActor;
use crate::system_routes::desired_from_membership;

#[derive(Clone)]
pub struct ControlPlaneActorArgs {
    pub transport: TransportConfig,
    pub node: CoreNode,
    pub network_id: Uuid,
    pub hostname: String,
    pub agent_version: &'static str,
    pub paths: StatePaths,
    /// Periodic snapshot poll interval (fallback when WS stalls).
    pub poll_secs: u64,
    /// Late-bound by the supervisor (`SetRouteActor`); `None` until wired.
    pub route_actor: Option<ActorRef<RouteActor>>,
    pub posture_actor: Option<ActorRef<PostureActor>>,
    pub ssh_registry: Option<ActorRef<SshRegistryActor>>,
}

#[derive(Clone)]
pub struct TransportConfig {
    pub control_url: String,
    pub endpoint_id: String,
    pub signing_key: SigningKey,
}

pub struct ControlPlaneActor {
    cfg: ControlPlaneActorArgs,
    client_tx: tokio::sync::mpsc::Sender<ClientMsg>,
    link: ControlPlaneLink,
    cancel: tokio_util::sync::CancellationToken,
    transport_task: Option<super::OwnedTask>,
    forwarder: Option<super::OwnedTask>,
    heartbeat: Option<super::OwnedTask>,
    poller: Option<super::OwnedTask>,
    version: Arc<ArcSwap<u64>>,
}

impl Actor for ControlPlaneActor {
    type Args = ControlPlaneActorArgs;
    type Error = Infallible;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        // Bounded control-plane channels (64–128).
        let (server_tx, server_rx) = tokio::sync::mpsc::channel::<ServerMsg>(128);
        let (client_tx, client_rx) = tokio::sync::mpsc::channel::<ClientMsg>(128);
        // Drive the node's own link object (when present) so Local API
        // status and event wiring observe the live transport. The link is a
        // read model; the actor owns the task driving it. Restarts reuse the
        // same link — it never becomes stale.
        let link = args
            .node
            .control_link
            .clone()
            .unwrap_or_else(|| ControlPlaneLink::new(args.transport.control_url.clone()));
        let transport = ControlTransport {
            control_url: args.transport.control_url.clone(),
            endpoint_id: args.transport.endpoint_id.clone(),
            signing_key: args.transport.signing_key.clone(),
            link: link.clone(),
        };
        let cancel = tokio_util::sync::CancellationToken::new();

        // Owned transport task. `run` only returns on cancellation; any
        // other return is an unexpected service death → abnormal failure.
        // Delivery uses bounded `send()` (never lossy `try_send`); the weak
        // ref keeps the task from holding the actor alive.
        let transport_task = {
            let done_cancel = cancel.clone();
            let transport_weak = actor_ref.downgrade();
            super::OwnedTask::spawn("control-transport", cancel.clone(), async move {
                transport
                    .run(server_tx, client_rx, done_cancel.clone())
                    .await;
                if done_cancel.is_cancelled() {
                    return;
                }
                let Some(actor) = transport_weak.upgrade() else {
                    return;
                };
                let _ = actor.tell(TransportExited).send().await;
            })
        };

        // Forwarder: ServerMsg -> actor tells. Actor-owned (cancelled and
        // joined in `on_stop`, aborted only on timeout). Weak ref so it
        // cannot keep the actor alive; ServerMsgs use bounded `send()` so
        // important commands apply backpressure instead of being dropped.
        let forwarder = {
            let weak = actor_ref.downgrade();
            let forward_cancel = cancel.clone();
            super::OwnedTask::spawn("control-forwarder", cancel.clone(), async move {
                let mut rx = server_rx;
                loop {
                    tokio::select! {
                        _ = forward_cancel.cancelled() => break,
                        msg = rx.recv() => {
                            let Some(msg) = msg else { break };
                            if let Some(actor) = weak.upgrade() {
                                if actor.tell(InboundServerMsg(msg)).send().await.is_err() {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            })
        };

        // Heartbeat driver (owned periodic tell, never blocks mailbox).
        let hb_weak = actor_ref.downgrade();
        let hb_cancel = cancel.clone();
        let heartbeat = super::OwnedTask::spawn_monitored(
            "control-heartbeat",
            cancel.clone(),
            actor_ref.downgrade(),
            HeartbeatExited,
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(15));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await;
                loop {
                    tokio::select! {
                        _ = hb_cancel.cancelled() => break,
                        _ = tick.tick() => {
                            if let Some(actor) = hb_weak.upgrade() {
                                let _ = actor.tell(SendHeartbeat).try_send();
                            } else {
                                break;
                            }
                        }
                    }
                }
            },
        );

        // Poll fallback driver (owned periodic tell; polls are idempotent so
        // a dropped/coalesced tick under pressure is harmless).
        let poll_secs = args.poll_secs.max(5);
        let poll_weak = actor_ref.downgrade();
        let poll_cancel = cancel.clone();
        let poller = super::OwnedTask::spawn_monitored(
            "control-poll",
            cancel.clone(),
            actor_ref.downgrade(),
            PollExited,
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(poll_secs));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await;
                loop {
                    tokio::select! {
                        _ = poll_cancel.cancelled() => break,
                        _ = tick.tick() => {
                            if let Some(actor) = poll_weak.upgrade() {
                                let _ = actor.tell(PollNow).try_send();
                            } else {
                                break;
                            }
                        }
                    }
                }
            },
        );

        let version = args.node.version.clone();
        // Route serve/send reports through this transport (overwrites the dead
        // bootstrap senders; bootstrap spawns no transport task).
        args.node.serves.set_client_tx(client_tx.clone());
        args.node.send.set_client_tx(client_tx.clone());
        // Say hello (best-effort, bounded).
        let _ = client_tx
            .send(ClientMsg::Hello {
                endpoint_id: "self".into(),
                agent_version: args.agent_version.to_string(),
                known_version: **version.load(),
            })
            .await;

        Ok(Self {
            cfg: args,
            client_tx,
            link,
            cancel,
            transport_task: Some(transport_task),
            forwarder: Some(forwarder),
            heartbeat: Some(heartbeat),
            poller: Some(poller),
            version,
        })
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Cancel everything, then join each owned task with the shared
        // bounded abort-after-timeout semantics: after this returns, none
        // of the actor's long-lived tasks may still be running.
        self.cancel.cancel();
        if let Some(task) = self.transport_task.take() {
            task.shutdown().await;
        }
        if let Some(task) = self.forwarder.take() {
            task.shutdown().await;
        }
        if let Some(task) = self.heartbeat.take() {
            task.shutdown().await;
        }
        if let Some(task) = self.poller.take() {
            task.shutdown().await;
        }
        // The transport task may have been aborted (failure path) without
        // marking the link: never leave a stale connected=true behind for
        // the next incarnation or the status read model.
        self.link
            .mark_disconnected(Some("control actor stopping".into()));
        Ok(())
    }
}

impl ControlPlaneActor {
    fn send_client(&self, msg: ClientMsg) {
        // Non-blocking: control channel is bounded; heartbeats/reports may
        // drop under extreme pressure rather than stall the mailbox.
        if self.client_tx.try_send(msg).is_err() {
            tracing::debug!("control client channel full; dropping message");
        }
    }

    async fn handle_server(&self, msg: ServerMsg) {
        let node = self.cfg.node.clone();
        match msg {
            ServerMsg::Snapshot(snap) => {
                node.pool.set_cloud_relay_urls(
                    snap.connectivity_relays
                        .iter()
                        .filter(|r| r.metering)
                        .map(|r| r.url.clone()),
                );
                if let Ok(m) = tunnet_core::sync::membership_for_network(&snap, self.cfg.network_id)
                {
                    tunnet_core::sync::apply_membership(
                        m,
                        &snap.org_policy,
                        snap.policy_verifying_key.as_deref(),
                        &node.routes,
                        &node.acl,
                        &self.version,
                        snap.version,
                        &self.cfg.transport.endpoint_id,
                        &self.cfg.hostname,
                        Some(self.cfg.paths.dir.as_path()),
                    );
                    // Typed dispatch: routes via RouteActor (bounded ask with timeout).
                    // The snapshot version travels with the work so a lagging
                    // task can never overwrite newer desired routes.
                    let desired = membership_desired(
                        &node,
                        &m.device_profile,
                        m.assigned_ipv4,
                        m.prefix,
                        &m.subnet_routes
                            .iter()
                            .filter(|r| r.via_endpoint_id != self.cfg.transport.endpoint_id)
                            .map(|r| r.cidr)
                            .collect::<Vec<_>>(),
                        m.device_profile.exit_node_endpoint_id.is_some(),
                    );
                    let snapshot_version = snap.version;
                    let route_actor = self.cfg.route_actor.clone();
                    let client_tx = self.client_tx.clone();
                    let policy = m.agent_policy.clone();
                    let paths = self.cfg.paths.clone();
                    let store = node.effective_config.clone();
                    let posture_actor = self.cfg.posture_actor.clone();
                    tokio::spawn(async move {
                        match route_actor {
                            Some(route_actor) => {
                                if let Ok(res) = tokio::time::timeout(
                                    Duration::from_secs(15),
                                    route_actor.ask(ApplyDesiredRoutes {
                                        desired,
                                        version: crate::actors::ControlVersion::Snapshot(
                                            snapshot_version,
                                        ),
                                    }),
                                )
                                .await
                                    && let Err(e) = res
                                {
                                    tracing::warn!(error = %e, "route apply via control plane failed");
                                }
                            }
                            None => {
                                tracing::debug!("route actor not wired yet; skipping route apply");
                            }
                        }
                        // Remote policy merge off the mailbox. Versioned like
                        // routes: a lagging snapshot must not overwrite the
                        // merge from a newer one.
                        if let Some(posture) = posture_actor {
                            let _ = posture
                                .tell(ApplyRemoteAgentPolicy {
                                    policy,
                                    paths,
                                    store,
                                    version: crate::actors::ControlVersion::Snapshot(
                                        snapshot_version,
                                    ),
                                })
                                .send()
                                .await;
                        } else {
                            let local = tunnet_core::TunnetConfig::try_load(&paths)
                                .ok()
                                .flatten()
                                .unwrap_or_default();
                            let effective = store.apply_remote(&local, policy);
                            let _ = client_tx
                                .send(ClientMsg::EffectiveConfigReport {
                                    config: effective,
                                    reported_at: jiff::Timestamp::now(),
                                })
                                .await;
                        }
                    });
                    tunnet_core::state::save_snapshot_cache(&self.cfg.paths, &snap).ok();
                    tracing::info!(
                        v = m.version,
                        peers = m.ipv4_peers.len(),
                        "snapshot from ws"
                    );
                } else if let Some(posture) = &self.cfg.posture_actor {
                    let _ = posture
                        .tell(ApplyRemoteAgentPolicy {
                            policy: snap.agent_policy.clone(),
                            paths: self.cfg.paths.clone(),
                            store: node.effective_config.clone(),
                            version: crate::actors::ControlVersion::Snapshot(snap.version),
                        })
                        .send()
                        .await;
                }
            }
            ServerMsg::Delta(delta) => {
                let network_name = node.routes.network_name();
                tunnet_core::sync::apply_delta(
                    &node.routes,
                    &self.version,
                    &delta,
                    &self.cfg.transport.endpoint_id,
                    self.cfg.network_id,
                    &network_name,
                );
                tracing::info!(
                    v = delta.version,
                    added = delta.added.len(),
                    removed = delta.removed.len(),
                    "delta received"
                );
            }
            ServerMsg::Policy(bundle) => node.acl.replace_bundle(bundle),
            ServerMsg::ForceReenroll { reason } => {
                tracing::error!(%reason, "control plane requested re-enrollment");
            }
            ServerMsg::Ping { nonce } => {
                self.send_client(ClientMsg::Pong { nonce });
                // Ping wake-up poll off the mailbox. Shares `poll_once` with
                // the periodic driver (stale-guarded, single implementation).
                if let Some(signed) = node.signed.clone() {
                    let routes = node.routes.clone();
                    let acl = node.acl.clone();
                    let version = self.version.clone();
                    let nid = self.cfg.network_id;
                    let eid = self.cfg.transport.endpoint_id.clone();
                    let hostname = self.cfg.hostname.clone();
                    let dir = self.cfg.paths.dir.clone();
                    tokio::spawn(async move {
                        tunnet_core::sync::poll_once(
                            &signed,
                            &version,
                            &routes,
                            &acl,
                            nid,
                            &eid,
                            &hostname,
                            Some(dir.as_path()),
                        )
                        .await;
                    });
                }
            }
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
                let mgr = node.serves.clone();
                let tx = self.client_tx.clone();
                tokio::spawn(async move {
                    let parsed_target = target_addr
                        .as_deref()
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
                    let result = mgr
                        .start(
                            serve_id.clone(),
                            port,
                            &protocol,
                            &internal_hostname,
                            certificate_pem.as_deref(),
                            private_key_pem.as_deref(),
                            tunnet_core::serve::ServeAcl {
                                access_mode,
                                allowed_tags,
                                allowed_endpoint_ids,
                            },
                            parsed_target,
                            true,
                        )
                        .await;
                    match result {
                        Ok(_) => {
                            let _ = tx.send(ClientMsg::ServeReady { serve_id }).await;
                        }
                        Err(e) => {
                            tracing::warn!(?e, %serve_id, "StartServe failed");
                            let _ = tx
                                .send(ClientMsg::ServeFailed {
                                    serve_id,
                                    error: e.to_string(),
                                })
                                .await;
                        }
                    }
                });
            }
            ServerMsg::ReconcileServes { serve_ids } => {
                let mgr = node.serves.clone();
                tokio::spawn(async move {
                    mgr.reconcile_managed(&serve_ids).await;
                });
            }
            ServerMsg::StopServe { serve_id } => {
                let mgr = node.serves.clone();
                let tx = self.client_tx.clone();
                tokio::spawn(async move {
                    let _ = mgr.stop_by_id(&serve_id).await;
                    let _ = tx.send(ClientMsg::ServeStopped { serve_id }).await;
                });
            }
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
                let mgr = node.tunnels.clone();
                let tx = self.client_tx.clone();
                tokio::spawn(async move {
                    let parsed_target = target_addr
                        .as_deref()
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
                    match mgr
                        .start(
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
                    {
                        Ok(info) => {
                            tracing::info!(url = %info.public_url, "OpenTunnel active");
                            let _ = tx.send(ClientMsg::TunnelReady { tunnel_id }).await;
                        }
                        Err(e) => {
                            tracing::warn!(?e, %tunnel_id, "OpenTunnel failed");
                            let _ = tx
                                .send(ClientMsg::TunnelFailed {
                                    tunnel_id,
                                    error: e.to_string(),
                                })
                                .await;
                        }
                    }
                });
            }
            ServerMsg::StopTunnel { tunnel_id } => {
                let mgr = node.tunnels.clone();
                let tx = self.client_tx.clone();
                tokio::spawn(async move {
                    let _ = mgr.stop(&tunnel_id);
                    let _ = tx.send(ClientMsg::TunnelStopped { tunnel_id }).await;
                });
            }
            ServerMsg::KillSshSession { session_id } => {
                if let Some(reg) = self.cfg.ssh_registry.clone() {
                    tokio::spawn(async move {
                        use super::ssh_registry::KillSession;
                        let _ = reg.ask(KillSession { session_id }).await;
                    });
                } else {
                    tracing::warn!(%session_id, "KillSshSession ignored (registry not wired)");
                }
            }
            ServerMsg::SendFile {
                transfer_id,
                path,
                target,
                message,
            } => {
                let mgr = node.send.clone();
                let tx = self.client_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = mgr
                        .send_file_with_id(
                            std::path::Path::new(&path),
                            &target,
                            message,
                            Some(transfer_id.clone()),
                        )
                        .await
                    {
                        tracing::warn!(?e, %transfer_id, "SendFile failed");
                        let _ = tx
                            .send(ClientMsg::TransferFailed {
                                transfer_id,
                                error: e.to_string(),
                                rejected: false,
                            })
                            .await;
                    }
                });
            }
            ServerMsg::AcceptTransfer { transfer_id } => {
                let mgr = node.send.clone();
                tokio::spawn(async move {
                    if let Err(e) = mgr.accept_pending(&transfer_id).await {
                        tracing::warn!(?e, %transfer_id, "AcceptTransfer failed");
                    }
                });
            }
            ServerMsg::RejectTransfer {
                transfer_id,
                reason,
            } => {
                let mgr = node.send.clone();
                tokio::spawn(async move {
                    if let Err(e) = mgr.reject_pending(&transfer_id, reason).await {
                        tracing::warn!(?e, %transfer_id, "RejectTransfer failed");
                    }
                });
            }
            ServerMsg::SetSendConsent {
                mode,
                inbox_path,
                pin_blobs,
            } => {
                let mgr = node.send.clone();
                tokio::spawn(async move {
                    let mut cfg = mgr.config();
                    if let Some(m) = tunnet_common::send::SendConsentMode::parse(&mode) {
                        cfg.consent = m;
                    }
                    if let Some(p) = inbox_path {
                        cfg.inbox_path = std::path::PathBuf::from(p);
                    }
                    cfg.pin_blobs = pin_blobs;
                    mgr.set_config(cfg);
                });
            }
            ServerMsg::PostureRecheck => {
                if let Some(p) = &self.cfg.posture_actor {
                    let p = p.clone();
                    tokio::spawn(async move {
                        let _ = p.tell(Recheck).send().await;
                    });
                }
            }
            ServerMsg::PostureConfigUpdate {
                interval_secs,
                enabled_collectors,
                custom_scripts,
            } => {
                if let Some(p) = &self.cfg.posture_actor {
                    let p = p.clone();
                    tokio::spawn(async move {
                        let _ = p
                            .tell(ApplyPostureConfig {
                                interval_secs,
                                enabled_collectors,
                                custom_scripts,
                            })
                            .send()
                            .await;
                    });
                }
            }
            ServerMsg::AgentConfigUpdate { policy } => {
                if let Some(p) = &self.cfg.posture_actor {
                    let p = p.clone();
                    let paths = self.cfg.paths.clone();
                    let store = node.effective_config.clone();
                    tokio::spawn(async move {
                        let _ = p
                            .tell(ApplyRemoteAgentPolicy {
                                policy,
                                paths,
                                store,
                                // Direct operator command, not snapshot
                                // state: explicit intent always applies.
                                version: crate::actors::ControlVersion::Local,
                            })
                            .send()
                            .await;
                    });
                }
            }
            ServerMsg::PostureStatus {
                postures,
                enforcement_action,
                grace_period_remaining_secs,
                remediation_messages,
            } => {
                if let Some(p) = &self.cfg.posture_actor {
                    let p = p.clone();
                    tokio::spawn(async move {
                        let _ = p
                            .tell(PostureStatusChanged {
                                postures,
                                enforcement_action,
                                grace_secs: grace_period_remaining_secs,
                                remediation: remediation_messages,
                            })
                            .send()
                            .await;
                    });
                }
            }
        }
    }
}

fn membership_desired(
    node: &CoreNode,
    profile: &tunnet_common::DeviceProfile,
    assigned: std::net::Ipv4Addr,
    prefix: u8,
    remote_subnets: &[ipnet::Ipv4Net],
    has_exit: bool,
) -> crate::system_routes::DesiredRoutes {
    // ifname resolved fromControlPlaneActor cfg at call site; use tunnet0 default here
    // and let RouteActor resolve the real index via DesiredRoutes.tun_if_index.
    let _ = node;
    desired_from_membership(
        "tunnet0",
        profile,
        assigned,
        prefix,
        remote_subnets,
        has_exit,
        &[],
    )
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

struct InboundServerMsg(ServerMsg);

impl Message<InboundServerMsg> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, msg: InboundServerMsg, _ctx: &mut Context<Self, Self::Reply>) {
        // Short dispatch only; long work is spawned off the mailbox.
        self.handle_server(msg.0).await;
    }
}

struct SendHeartbeat;

impl Message<SendHeartbeat> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: SendHeartbeat, _ctx: &mut Context<Self, Self::Reply>) {
        let (active_conns, bytes_tx, bytes_rx) = self.cfg.node.pool.heartbeat_counters();
        self.send_client(ClientMsg::Heartbeat {
            active_conns,
            bytes_tx,
            bytes_rx,
        });
        let bytes = self.cfg.node.pool.cloud_relay_meter().take();
        if bytes > 0 {
            self.send_client(ClientMsg::CloudRelayUsage { bytes });
        }
    }
}

/// Periodic snapshot poll (fallback when WS stalls). Runs off the mailbox.
struct PollNow;

impl Message<PollNow> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: PollNow, _ctx: &mut Context<Self, Self::Reply>) {
        if let Some(signed) = self.cfg.node.signed.clone() {
            let node = self.cfg.node.clone();
            let version = self.version.clone();
            let network_id = self.cfg.network_id;
            let endpoint_id = self.cfg.transport.endpoint_id.clone();
            let hostname = self.cfg.hostname.clone();
            let dir = self.cfg.paths.dir.clone();
            tokio::spawn(async move {
                tunnet_core::sync::poll_once(
                    &signed,
                    &version,
                    &node.routes,
                    &node.acl,
                    network_id,
                    &endpoint_id,
                    &hostname,
                    Some(dir.as_path()),
                )
                .await;
            });
        }
    }
}

pub struct GetControlStatus;
#[derive(Debug, Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct ControlStatus {
    pub connected: bool,
    pub url: String,
}

impl Message<GetControlStatus> for ControlPlaneActor {
    type Reply = ControlStatus;
    async fn handle(
        &mut self,
        _msg: GetControlStatus,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let snap = self.link.snapshot();
        ControlStatus {
            connected: snap.connected,
            url: snap.url,
        }
    }
}

/// The owned transport task ended without cancellation. Abnormal: the
/// supervisor must restart us (the transport is recreated in `on_start`).
/// Normal network disconnects never produce this — the transport reconnects
/// internally and only returns when cancelled.
struct TransportExited;

impl Message<TransportExited> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: TransportExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("control transport unexpectedly terminated");
    }
}

/// An owned periodic driver ended without cancellation. Abnormal:
/// supervision must restart us.
struct HeartbeatExited;
struct PollExited;

impl Message<HeartbeatExited> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: HeartbeatExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("control heartbeat driver unexpectedly terminated");
    }
}

impl Message<PollExited> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: PollExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("control poll driver unexpectedly terminated");
    }
}

/// Forward a `ClientMsg` into the transport (e.g. posture reports).
/// Bounded; drops under extreme pressure rather than stalling the sender.
pub struct ForwardClientMsg(pub ClientMsg);

impl Message<ForwardClientMsg> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, msg: ForwardClientMsg, _ctx: &mut Context<Self, Self::Reply>) {
        self.send_client(msg.0);
    }
}

/// Late-bind the route actor (filled by the supervisor after the dataplane
/// tree starts; `ActorRef`s stay valid across supervised restarts).
pub struct SetRouteActor(pub Option<ActorRef<RouteActor>>);

impl Message<SetRouteActor> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, msg: SetRouteActor, _ctx: &mut Context<Self, Self::Reply>) {
        self.cfg.route_actor = msg.0;
    }
}

/// Late-bind the posture actor.
pub struct SetPostureActor(pub Option<ActorRef<PostureActor>>);

impl Message<SetPostureActor> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, msg: SetPostureActor, _ctx: &mut Context<Self, Self::Reply>) {
        self.cfg.posture_actor = msg.0;
    }
}

pub struct ShutdownControl;
impl Message<ShutdownControl> for ControlPlaneActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ShutdownControl, ctx: &mut Context<Self, Self::Reply>) {
        self.cancel.cancel();
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::test_support::test_node;
    use kameo::actor::Spawn;
    use kameo::supervision::{RestartPolicy, SupervisionStrategy};

    async fn test_args(node: CoreNode) -> ControlPlaneActorArgs {
        let route = RouteActor::spawn_with_mailbox(
            super::super::routes::RouteActorArgs,
            kameo::mailbox::bounded(super::super::ROUTE_MAILBOX),
        );
        let ssh = SshRegistryActor::spawn_with_mailbox(
            (),
            kameo::mailbox::bounded(super::super::SSH_REGISTRY_MAILBOX),
        );
        let endpoint_id = node.endpoint_id_hex();
        let signing_key = node.identity.signing_key.clone();
        let paths = node.paths.clone();
        ControlPlaneActorArgs {
            transport: TransportConfig {
                // Nothing listens here: connect fails fast (refused) and the
                // transport backs off — offline-safe.
                control_url: "http://127.0.0.1:9".into(),
                endpoint_id,
                signing_key,
            },
            node,
            network_id: Uuid::nil(),
            hostname: "test-host".into(),
            agent_version: env!("CARGO_PKG_VERSION"),
            paths,
            poll_secs: 30,
            route_actor: Some(route),
            posture_actor: None,
            ssh_registry: Some(ssh),
        }
    }

    struct Sup;
    impl Actor for Sup {
        type Args = ();
        type Error = Infallible;
        async fn on_start(
            _args: Self::Args,
            _actor_ref: ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            Ok(Sup)
        }
        fn supervision_strategy() -> SupervisionStrategy {
            SupervisionStrategy::OneForOne
        }
    }

    #[tokio::test]
    async fn transport_death_recovers_functional_actor() {
        let (node, _tmp) = test_node().await;
        let sup = Sup::spawn(());
        sup.wait_for_startup().await;
        let control = ControlPlaneActor::supervise(&sup, test_args(node).await)
            .restart_policy(RestartPolicy::Transient)
            .restart_limit(5, Duration::from_secs(60))
            .spawn_with_mailbox(kameo::mailbox::bounded(super::super::CONTROL_MAILBOX))
            .await;
        control.wait_for_startup().await;
        // Transport churns (refused) but the actor lives and answers.
        let status: ControlStatus = control.ask(GetControlStatus).await.expect("status");
        assert!(!status.connected);
        // Unexpected owned-task death must recover via supervision.
        let _ = control.tell(TransportExited).send().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if control.ask(GetControlStatus).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("control actor did not recover after transport death");
        let _ = sup.stop_gracefully().await;
        tokio::time::timeout(Duration::from_secs(15), sup.wait_for_shutdown())
            .await
            .expect("shutdown drain");
    }
}
