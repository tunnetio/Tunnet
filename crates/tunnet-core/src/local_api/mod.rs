//! Local Management API - HTTP JSON over Unix domain socket / Windows named pipe.

#[cfg(feature = "local_api")]
pub mod auth;
#[cfg(feature = "local_api")]
pub mod bootstrap;
#[cfg(feature = "local_api")]
pub mod bootstrap_router;
#[cfg(feature = "local_api")]
pub mod dataplane;
#[cfg(feature = "local_api")]
pub mod handlers;
#[cfg(feature = "local_api")]
pub mod router;
#[cfg(feature = "local_api")]
pub mod server;
#[cfg(feature = "local_api")]
pub mod state;
#[cfg(feature = "local_api")]
pub mod transport;

#[cfg(feature = "local_api")]
pub use bootstrap::BootstrapOps;
#[cfg(feature = "local_api")]
pub use bootstrap_router::BootstrapApiState;
#[cfg(feature = "local_api")]
pub use dataplane::{DataPlaneControl, DataPlaneStatusSnapshot};
#[cfg(feature = "local_api")]
pub use server::LocalApiServer;
#[cfg(feature = "local_api")]
pub use server::spawn as spawn_local_api;
#[cfg(feature = "local_api")]
pub use server::spawn_bootstrap as spawn_bootstrap_api;
#[cfg(feature = "local_api")]
pub use state::LocalApiState;
#[cfg(feature = "local_api")]
pub use transport::{default_api_path, endpoint_reachable};

/// Load persisted agent state (for display / network selection).
#[cfg(feature = "local_api")]
pub fn discover_agent_state(
    state_dir: Option<&str>,
) -> anyhow::Result<crate::state::PersistedState> {
    use anyhow::Context;
    let paths = crate::state::StatePaths::resolve(state_dir);
    crate::state::PersistedState::try_load(&paths)?.with_context(|| {
        format!(
            "not connected to a network yet (no state in {}). \
                 Use `tunnet create` for Direct or `tunnet enroll` for Managed",
            paths.state_file().display()
        )
    })
}

/// Discover primary network id from persisted agent state on this machine.
#[cfg(feature = "local_api")]
pub fn discover_network_id(
    state_dir: Option<&str>,
) -> anyhow::Result<(uuid::Uuid, crate::state::PersistedState)> {
    use anyhow::Context;
    let persisted = discover_agent_state(state_dir)?;
    Ok((
        persisted
            .primary_network_id()
            .context("persisted state has no network id")?,
        persisted,
    ))
}
