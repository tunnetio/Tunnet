//! One SSH listener per active mesh address/network.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use russh::server::Config;
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;

use super::authorize::BindingPolicy;
use super::host_key::load_or_create_host_key;
use super::intercept::{SSH_INTERNAL_PORT, SshIntercept};
use super::server::{SshHandler, SshServeDeps};
use tunnet_core::StatePaths;

#[derive(Clone)]
pub struct SshBinding {
    pub mesh_ip: Ipv4Addr,
    pub network_id: uuid::Uuid,
    pub network_name: String,
    pub policy: BindingPolicy,
}

pub async fn spawn_ssh_listener(
    bindings: Vec<SshBinding>,
    intercept: SshIntercept,
    paths: &StatePaths,
    deps: SshServeDeps,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    anyhow::ensure!(!bindings.is_empty(), "no SSH bindings");
    let host_key = load_or_create_host_key(paths)?;
    let addresses = bindings.iter().map(|b| b.mesh_ip).collect();
    let mut listeners = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let listener = TcpListener::bind((binding.mesh_ip, SSH_INTERNAL_PORT)).await?;
        tracing::info!(
            mesh_ip = %binding.mesh_ip,
            network_id = %binding.network_id,
            network = %binding.network_name,
            port = SSH_INTERNAL_PORT,
            "embedded SSH listening"
        );
        listeners.push((listener, binding));
    }

    intercept.set(addresses);
    let handle = tokio::spawn(async move {
        let _intercept = ListenerIntercept {
            intercept,
            forwarding: deps.forwarding.clone(),
            routes: deps.routes.clone(),
        };
        let mut workers = tokio::task::JoinSet::new();
        for (listener, binding) in listeners {
            let deps = deps.clone();
            let host_key = host_key.clone();
            workers.spawn(async move {
                let mut sessions = tokio::task::JoinSet::new();
                loop {
                    let accepted = tokio::select! {
                        result = listener.accept(), if sessions.len() < 64 => result,
                        Some(_) = sessions.join_next(), if !sessions.is_empty() => continue,
                    };
                    let (socket, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(?e, network_id = %binding.network_id, "ssh accept failed");
                            break;
                        }
                    };
                    let local = socket
                        .local_addr()
                        .unwrap_or_else(|_| (Ipv4Addr::UNSPECIFIED, SSH_INTERNAL_PORT).into());
                    let deps = deps.clone();
                    let binding = binding.clone();
                    let host_key = host_key.clone();
                    sessions.spawn(async move {
                        let mut methods = MethodSet::empty();
                        methods.push(MethodKind::None);
                        if matches!(binding.policy, BindingPolicy::Managed) {
                            methods.push(MethodKind::KeyboardInteractive);
                        }
                        let config = Arc::new(Config {
                            inactivity_timeout: Some(Duration::from_secs(3600)),
                            auth_rejection_time: Duration::from_secs(1),
                            auth_rejection_time_initial: Some(Duration::from_secs(0)),
                            keys: vec![host_key],
                            methods,
                            ..Default::default()
                        });
                        let handler = SshHandler::new(deps, binding, peer, local);
                        match russh::server::run_stream(config, socket, handler).await {
                            Ok(session) => {
                                if let Err(e) = session.await {
                                    tracing::debug!(?e, %peer, "ssh session ended");
                                }
                            }
                            Err(e) => tracing::debug!(?e, %peer, "ssh handshake failed"),
                        }
                    });
                }
            });
        }
        let _ = workers.join_next().await;
        workers.shutdown().await;
    });
    Ok(handle)
}

struct ListenerIntercept {
    intercept: SshIntercept,
    forwarding: tunnet_core::ForwardingStore,
    routes: tunnet_core::RoutingTable,
}

impl Drop for ListenerIntercept {
    fn drop(&mut self) {
        self.intercept.set(Default::default());
        self.forwarding
            .set_ssh_addrs(&self.routes, Default::default());
    }
}
