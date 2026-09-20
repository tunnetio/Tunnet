//! Embedder-installed OS capabilities. Mesh and routing policy stay in the agent.

#[cfg(any(target_os = "android", all(test, unix)))]
pub mod tun;
