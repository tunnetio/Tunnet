//! Agent IPC v2 - local request/response protocol for the TunTun CLI.
//!
//! See [`protocol`] for wire types, [`server`] for the agent-side listener,
//! and [`client`] for CLI usage.

pub mod client;
pub mod dataplane;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::{IpcClient, discover_network_id};
pub use dataplane::{DataPlaneCmdRx, DataPlaneHandle, recv_cmd};
pub use protocol::*;
pub use server::{AgentIpcState, spawn as spawn_ipc_server};
pub use transport::default_ipc_path;
