//! `PostureActor`: single owner of posture engine + reporter lifecycle.
//!
//! Replaces detached `PostureRuntime::spawn` tasks and callback closures that
//! spawned additional work. Long collector work runs off the mailbox via
//! `ctx.pipe`; actor-owned loops use explicit `CancellationToken`+`JoinHandle`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use jiff::Timestamp;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible};
use kameo::message::{Context, Message};
use tunnet_common::posture::CustomScriptConfig;
use tunnet_common::ws::ClientMsg;
use tunnet_posture::{PostureEngine, PostureEngineConfig, PostureValue};

#[derive(Clone)]
pub struct PostureActorArgs {
    pub agent_version: String,
    pub control: ActorRef<super::control::ControlPlaneActor>,
    pub src_posture_ok: Arc<ArcSwap<bool>>,
    pub authorization_gate: Arc<parking_lot::RwLock<()>>,
    pub forwarding: tunnet_core::ForwardingStore,
}

pub struct PostureActor {
    engine: Arc<PostureEngine>,
    control: ActorRef<super::control::ControlPlaneActor>,
    src_posture_ok: Arc<ArcSwap<bool>>,
    authorization_gate: Arc<parking_lot::RwLock<()>>,
    forwarding: tunnet_core::ForwardingStore,
    cancel: tokio_util::sync::CancellationToken,
    tasks: Vec<super::OwnedTask>,
    last_policy_version: Option<u64>,
}

impl Actor for PostureActor {
    type Args = PostureActorArgs;
    type Error = Infallible;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let engine = Arc::new(PostureEngine::with_default_collectors(
            PostureEngineConfig {
                tunnet_version: args.agent_version,
                ..PostureEngineConfig::default()
            },
        ));
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut actor = Self {
            engine,
            control: args.control,
            src_posture_ok: args.src_posture_ok,
            authorization_gate: args.authorization_gate,
            forwarding: args.forwarding,
            cancel,
            tasks: Vec::new(),
            last_policy_version: None,
        };
        actor.start_owned_tasks(actor_ref);
        // Initial collection without blocking the mailbox.
        Ok(actor)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            task.shutdown_with(std::time::Duration::from_secs(3)).await;
        }
        Ok(())
    }
}

impl PostureActor {
    fn start_owned_tasks(&mut self, actor_ref: ActorRef<Self>) {
        let mut change_rx = self.engine.subscribe();
        // Engine run loop (owned, cancellable).
        {
            let engine = self.engine.clone();
            let cancel = self.cancel.clone();
            let run_cancel = cancel.clone();
            let weak = actor_ref.downgrade();
            self.tasks.push(super::OwnedTask::spawn_monitored(
                "posture-engine",
                cancel,
                weak,
                EngineExited,
                async move {
                    engine.run(run_cancel).await;
                },
            ));
        }
        // Delta reporter loop (owned, cancellable). Reports forward through
        // the control actor so posture never holds transport channels.
        {
            let control = self.control.clone();
            let cancel = self.cancel.clone();
            let report_cancel = cancel.clone();
            let weak = actor_ref.downgrade();
            self.tasks.push(super::OwnedTask::spawn_monitored(
                "posture-reporter",
                cancel,
                weak,
                ReporterExited,
                async move {
                loop {
                    tokio::select! {
                        _ = report_cancel.cancelled() => break,
                        changed = change_rx.recv() => {
                            match changed {
                                Ok(event) => {
                                    let msg = ClientMsg::PostureReport {
                                        full: true,
                                        attributes: json_map(&event.attributes),
                                        collected_at: event.collected_at,
                                    };
                                    if control
                                        .tell(super::control::ForwardClientMsg(msg))
                                        .send()
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            }
                        }
                    }
                }
            }));
        }
    }
}

/// An owned posture service loop ended without cancellation. Abnormal:
/// supervision must restart us.
struct EngineExited;
struct ReporterExited;

impl Message<EngineExited> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: EngineExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("posture engine unexpectedly terminated");
    }
}

impl Message<ReporterExited> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ReporterExited, _ctx: &mut Context<Self, Self::Reply>) {
        panic!("posture reporter unexpectedly terminated");
    }
}

fn json_map(attrs: &HashMap<String, PostureValue>) -> HashMap<String, serde_json::Value> {
    attrs
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Messages (all serialize through the actor; long work is piped)
// ---------------------------------------------------------------------------

pub struct Recheck;

pub struct ApplyPostureConfig {
    pub interval_secs: u64,
    pub enabled_collectors: Vec<String>,
    pub custom_scripts: Vec<CustomScriptConfig>,
}

pub struct ApplyRemoteAgentPolicy {
    pub policy: tunnet_common::RemoteAgentPolicy,
    pub paths: tunnet_core::StatePaths,
    pub store: tunnet_core::EffectiveConfigStore,
    /// Snapshot version guard: stale snapshots must not overwrite the merge
    /// from a newer one. Direct operator commands use `Local`.
    pub version: super::ControlVersion,
}

pub struct PostureStatusChanged {
    pub postures: Vec<tunnet_common::posture::PostureEvalResult>,
    pub enforcement_action: String,
    pub grace_secs: Option<u64>,
    pub remediation: Vec<String>,
}

pub struct CollectorChanged;

pub struct GetPostureEngine;

pub struct ShutdownPosture;

impl Message<Recheck> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: Recheck, ctx: &mut Context<Self, Self::Reply>) {
        let engine = self.engine.clone();
        ctx.pipe(async move {
            if let Err(e) = engine.collect_once().await {
                tracing::warn!(?e, "posture recheck failed");
            }
            CollectorChanged
        });
    }
}

impl Message<ApplyPostureConfig> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, msg: ApplyPostureConfig, ctx: &mut Context<Self, Self::Reply>) {
        tracing::info!(
            interval_secs = msg.interval_secs,
            collectors = msg.enabled_collectors.len(),
            scripts = msg.custom_scripts.len(),
            "posture config update received"
        );
        let engine = self.engine.clone();
        let collectors = if msg.enabled_collectors.is_empty() {
            None
        } else {
            Some(msg.enabled_collectors)
        };
        ctx.pipe(async move {
            engine
                .apply_config(
                    Duration::from_secs(msg.interval_secs.max(30)),
                    collectors,
                    msg.custom_scripts,
                )
                .await;
            if let Err(e) = engine.collect_once().await {
                tracing::warn!(?e, "posture config recheck failed");
            }
            CollectorChanged
        });
    }
}

impl Message<ApplyRemoteAgentPolicy> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, msg: ApplyRemoteAgentPolicy, ctx: &mut Context<Self, Self::Reply>) {
        if !super::accept_version(&mut self.last_policy_version, msg.version) {
            tracing::debug!(version = ?msg.version, "ignoring stale remote agent policy");
            return;
        }
        let engine = self.engine.clone();
        let control = self.control.clone();
        ctx.pipe(async move {
            let local = tunnet_core::TunnetConfig::try_load(&msg.paths)
                .ok()
                .flatten()
                .unwrap_or_default();
            let effective = msg.store.apply_remote(&local, msg.policy.clone());
            let interval = effective.posture_interval_secs.value;
            let collectors = if effective.posture_enabled_collectors.value.is_empty() {
                None
            } else {
                Some(effective.posture_enabled_collectors.value.clone())
            };
            let scripts = msg
                .policy
                .posture
                .as_ref()
                .map(|p| p.custom_scripts.clone())
                .unwrap_or_default();
            engine
                .apply_config(Duration::from_secs(interval.max(30)), collectors, scripts)
                .await;
            if let Err(e) = engine.collect_once().await {
                tracing::warn!(?e, "posture recollect after config update failed");
            }
            // Report merged config back to control plane.
            let _ = control
                .tell(super::control::ForwardClientMsg(
                    ClientMsg::EffectiveConfigReport {
                        config: effective,
                        reported_at: Timestamp::now(),
                    },
                ))
                .send()
                .await;
            CollectorChanged
        });
    }
}

impl Message<PostureStatusChanged> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, msg: PostureStatusChanged, _ctx: &mut Context<Self, Self::Reply>) {
        let failing = msg.postures.iter().filter(|p| !p.passed).count();
        // Enforcement revoke is a local kill switch. Named proof is the snapshot claim.
        let ok = msg.enforcement_action != "revoke";
        let changed = {
            let _guard = self.authorization_gate.write();
            if **self.src_posture_ok.load() == ok {
                false
            } else {
                self.src_posture_ok.store(Arc::new(ok));
                true
            }
        };
        if changed {
            self.forwarding.notify_authorization_changed();
        }
        if failing > 0 {
            tracing::warn!(
                enforcement_action = %msg.enforcement_action,
                grace_secs = ?msg.grace_secs,
                failing,
                remediation = ?msg.remediation,
                src_posture_ok = ok,
                "device posture non-compliant"
            );
        } else {
            tracing::debug!(enforcement_action = %msg.enforcement_action, "device posture compliant");
        }
    }
}

impl Message<CollectorChanged> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: CollectorChanged, _ctx: &mut Context<Self, Self::Reply>) {}
}

impl Message<GetPostureEngine> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: GetPostureEngine, _ctx: &mut Context<Self, Self::Reply>) {}
}

impl Message<ShutdownPosture> for PostureActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ShutdownPosture, ctx: &mut Context<Self, Self::Reply>) {
        // `on_stop` cancels and joins owned tasks with a bounded timeout.
        ctx.stop();
    }
}
