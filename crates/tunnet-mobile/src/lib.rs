//! Tunnet agent embedded in a mobile app process.
//!
//! The agent normally runs as a privileged daemon. On Android that is
//! impossible: an app cannot spawn a daemon, open a TUN, or write system routes.
//! Instead the whole agent runs in-process inside the app's `VpnService`, which
//! supplies the tunnel and owns the routing table.
//!
//! Two layers, split so the JVM-free half stays testable on the host:
//!
//! * [`session`] - owns the tokio executor around [`tunnet_agent::AgentRuntime`].
//! * `jni_bridge` - the `Java_..._native*` exports and the `TunProvider` that
//!   calls back into `VpnService.Builder`. Android-only.
//!
//! The app never speaks the mesh protocol. It hosts the agent and drives it
//! through the in-process runtime handle.

pub mod session;

#[cfg(target_os = "android")]
mod jni_bridge;

pub use session::AgentSession;
