//! Destination-side Tunnet SSH server.
//!
//! Tunnet authenticates the remote principal at the mesh layer. SSH `none`
//! means SSH-layer credentials are unnecessary because that identity is
//! already established. Policy then authorizes a destination OS account, and
//! the platform backend runs the session as that account.

mod account;
mod authorize;
mod capabilities;
mod exec;
mod host_key;
mod intercept;
mod listener;
mod server;
mod session_child;
mod sftp;
mod tee;

pub use host_key::host_pubkey_openssh;
pub use intercept::SshIntercept;
pub use listener::{SshBinding, spawn_ssh_listener};
pub use server::SshServeDeps;
pub use session_child::maybe_run;

use tunnet_core::CoreNode;
use tunnet_core::agent_config::TunnetConfig;

pub fn bindings_from_runtime(
    node: &CoreNode,
    is_direct: bool,
    managed_network_id: uuid::Uuid,
    managed_network_name: &str,
    cfg: &TunnetConfig,
) -> Vec<SshBinding> {
    if is_direct {
        node.direct
            .iter()
            .filter_map(|(network_id, runtime)| {
                let policy = authorize::BindingPolicy::from_direct(
                    &cfg.ssh_for_network(&runtime.state.network_name),
                )?;
                Some(SshBinding {
                    mesh_ip: runtime.state.self_record.ipv4,
                    network_id: *network_id,
                    network_name: runtime.state.network_name.clone(),
                    policy,
                })
            })
            .collect()
    } else {
        vec![SshBinding {
            mesh_ip: node.self_ipv4,
            network_id: managed_network_id,
            network_name: managed_network_name.to_string(),
            policy: authorize::BindingPolicy::Managed,
        }]
    }
}
