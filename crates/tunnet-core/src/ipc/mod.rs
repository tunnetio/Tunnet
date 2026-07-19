//! Agent IPC v3 - local request/response protocol for the Tunnet CLI.
//!
//! See [`protocol`] for wire types, [`server`] for the agent-side listener,
//! and [`client`] for CLI usage.

pub mod protocol;

#[cfg(feature = "ipc")]
pub mod client;
#[cfg(feature = "ipc")]
pub mod dataplane;
#[cfg(feature = "ipc")]
pub mod server;
#[cfg(feature = "ipc")]
pub mod transport;

#[cfg(feature = "ipc")]
pub use client::{IpcClient, discover_agent_state, discover_network_id};
#[cfg(feature = "ipc")]
pub use dataplane::{DataPlaneCmdRx, DataPlaneHandle, recv_cmd};
pub use protocol::*;
#[cfg(feature = "ipc")]
pub use server::{AgentIpcState, spawn as spawn_ipc_server};
#[cfg(feature = "ipc")]
pub use transport::{default_ipc_path, endpoint_reachable};
