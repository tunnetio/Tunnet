//! TCP listener for Tunnet SSH on mesh_ip:SSH_INTERNAL_PORT.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use russh::server::Config;
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;

use super::host_key::load_or_create_host_key;
use super::server::{SshHandler, SshServeDeps};
use crate::ssh_nat::SSH_INTERNAL_PORT;

pub async fn spawn_ssh_listener(
    mesh_ip: Ipv4Addr,
    paths: &tunnet_core::StatePaths,
    deps: SshServeDeps,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let host_key = load_or_create_host_key(paths)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::None);
    methods.push(MethodKind::KeyboardInteractive);

    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        methods,
        ..Default::default()
    });

    let bind = (mesh_ip, SSH_INTERNAL_PORT);
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%mesh_ip, port = SSH_INTERNAL_PORT, "SSH server listening (NAT maps :22)");

    let handle = tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "ssh accept failed");
                    continue;
                }
            };
            let config = config.clone();
            let deps = deps.clone();
            tokio::spawn(async move {
                let handler = SshHandler::new(deps, peer);
                match russh::server::run_stream(config, socket, handler).await {
                    Ok(session) => {
                        if let Err(e) = session.await {
                            tracing::debug!(?e, %peer, "ssh session ended");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(?e, %peer, "ssh handshake failed");
                    }
                }
            });
        }
    });
    Ok(handle)
}
