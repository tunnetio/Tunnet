//! Kameo-free control surface for pausing / resuming the agent data plane.
//!
//! HTTP handlers receive a narrow [`DataPlaneControl`] interface. The agent
//! implements it with Kameo `ReplyRecipient`s; frequently-read status is served
//! from a cheap atomic snapshot, never via an actor round-trip.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;

/// Narrow control capability used by the Local Management API.
///
/// Implemented in `tunnet-agent` on top of the `DataPlaneActor`. Kept in core
/// as a plain async trait so core never depends on Kameo.
#[async_trait]
pub trait DataPlaneControl: Send + Sync {
    fn is_up(&self) -> bool;
    async fn bring_up(&self) -> Result<(), String>;
    async fn bring_down(&self) -> Result<(), String>;
    /// Health detail for status rendering. Defaults to unknown/down;
    /// the actor-backed implementation reads the shared snapshot.
    fn data_plane_info(&self) -> tunnet_common::local_api::DataPlaneInfo {
        tunnet_common::local_api::DataPlaneInfo {
            state: DataPlaneState::Down.to_string(),
            outbound_alive: false,
            restart_count: 0,
            generation: 0,
            last_error: None,
        }
    }
}

/// Cheap shared read model for dataplane status.
///
/// The `DataPlaneActor` is the only writer; HTTP GETs read this directly.
/// A dataplane with a dead packet worker must never report healthy: the
/// `state()` below distinguishes Up / Degraded / Restarting / Down from
/// the worker-liveness and restart flags (see the crash-loop incident
/// where `data plane up` masked a dead outbound loop).
#[derive(Clone, Default, Debug)]
pub struct DataPlaneStatusSnapshot {
    up: Arc<AtomicBool>,
    outbound_alive: Arc<AtomicBool>,
    restarting: Arc<AtomicBool>,
    restart_count: Arc<AtomicU64>,
    generation: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
}

/// Dataplane health state (rendered by `tunnet status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneState {
    Up,
    Degraded,
    Restarting,
    Down,
}

impl std::fmt::Display for DataPlaneState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "up"),
            Self::Degraded => write!(f, "degraded"),
            Self::Restarting => write!(f, "restarting"),
            Self::Down => write!(f, "down"),
        }
    }
}

impl DataPlaneStatusSnapshot {
    pub fn new(up: bool) -> Self {
        Self {
            up: Arc::new(AtomicBool::new(up)),
            outbound_alive: Arc::new(AtomicBool::new(up)),
            restarting: Arc::new(AtomicBool::new(false)),
            restart_count: Arc::new(AtomicU64::new(0)),
            generation: Arc::new(AtomicU64::new(0)),
            last_error: Arc::new(Mutex::new(None)),
        }
    }

    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }

    pub fn outbound_alive(&self) -> bool {
        self.outbound_alive.load(Ordering::SeqCst)
    }

    pub fn set_up(&self, v: bool) {
        self.up.store(v, Ordering::SeqCst);
    }

    pub fn set_outbound_alive(&self, v: bool) {
        self.outbound_alive.store(v, Ordering::SeqCst);
    }

    pub fn set_restarting(&self, v: bool) {
        self.restarting.store(v, Ordering::SeqCst);
    }

    pub fn set_generation(&self, v: u64) {
        self.generation.store(v, Ordering::SeqCst);
    }

    pub fn note_restart(&self, error: String) {
        self.restart_count.fetch_add(1, Ordering::SeqCst);
        *self.last_error.lock() = Some(error);
    }

    pub fn set_last_error(&self, error: String) {
        *self.last_error.lock() = Some(error);
    }

    pub fn restart_count(&self) -> u64 {
        self.restart_count.load(Ordering::SeqCst)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().clone()
    }

    pub fn state(&self) -> DataPlaneState {
        if self.restarting.load(Ordering::SeqCst) {
            DataPlaneState::Restarting
        } else if self.up.load(Ordering::SeqCst) {
            if self.outbound_alive.load(Ordering::SeqCst) {
                DataPlaneState::Up
            } else {
                DataPlaneState::Degraded
            }
        } else {
            DataPlaneState::Down
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_state_transitions() {
        // A dead packet worker must never read as healthy: crash sets
        // restarting (not up), bring-up clears it, bring-down clears all.
        let s = DataPlaneStatusSnapshot::new(false);
        assert_eq!(s.state(), DataPlaneState::Down);
        s.set_up(true);
        s.set_outbound_alive(true);
        assert_eq!(s.state(), DataPlaneState::Up);
        // Worker death with the device half up: degraded, not up.
        s.set_outbound_alive(false);
        assert_eq!(s.state(), DataPlaneState::Degraded);
        // Unexpected end: restarting + error + count, published before
        // supervision restarts the actor.
        s.note_restart("outbound TUN loop unexpectedly terminated".into());
        s.set_restarting(true);
        assert_eq!(s.state(), DataPlaneState::Restarting);
        assert_eq!(s.restart_count(), 1);
        assert_eq!(
            s.last_error().as_deref(),
            Some("outbound TUN loop unexpectedly terminated")
        );
        // Successful bring-up recovers fully.
        s.set_up(true);
        s.set_restarting(false);
        s.set_outbound_alive(true);
        s.set_generation(7);
        assert_eq!(s.state(), DataPlaneState::Up);
        assert_eq!(s.generation(), 7);
        // Intentional shutdown: plain down.
        s.set_up(false);
        s.set_restarting(false);
        s.set_outbound_alive(false);
        assert_eq!(s.state(), DataPlaneState::Down);
    }
}
