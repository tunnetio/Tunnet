//! Host-provided constraints on discovery. Not mesh policy.
//!
//! The host reports whether LAN is currently usable. Defaults to available so
//! desktop daemons are unchanged. Embedders set this from platform capability
//! (for example Android local-network permission) before starting the agent.

use std::sync::atomic::{AtomicBool, Ordering};

use tunnet_core::direct::ConnectivityOptions;

static LAN_AVAILABLE: AtomicBool = AtomicBool::new(true);

pub fn set_lan_available(available: bool) {
    LAN_AVAILABLE.store(available, Ordering::SeqCst);
}

pub fn lan_available() -> bool {
    LAN_AVAILABLE.load(Ordering::SeqCst)
}

/// Clear LAN discovery flags when the host cannot use the local network.
pub fn constrain_lan(opts: &mut ConnectivityOptions) {
    if !lan_available() {
        opts.enable_mdns = false;
        opts.enable_lan_discovery = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn denied_host_disables_lan_flags() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = lan_available();
        set_lan_available(false);
        let mut opts = ConnectivityOptions::direct_default(true);
        constrain_lan(&mut opts);
        assert!(!opts.enable_mdns);
        assert!(!opts.enable_lan_discovery);
        assert!(opts.enable_dht);
        set_lan_available(previous);
    }

    #[test]
    fn granted_host_leaves_policy_flags_alone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = lan_available();
        set_lan_available(true);
        let mut opts = ConnectivityOptions::direct_default(true);
        constrain_lan(&mut opts);
        assert!(opts.enable_mdns);
        assert!(opts.enable_lan_discovery);
        set_lan_available(previous);
    }

    #[test]
    fn lan_available_does_not_force_mdns_on() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = lan_available();
        set_lan_available(true);
        let mut opts = ConnectivityOptions::direct_default(true);
        opts.enable_mdns = false;
        constrain_lan(&mut opts);
        assert!(!opts.enable_mdns);
        assert!(opts.enable_dht);
        set_lan_available(previous);
    }
}
