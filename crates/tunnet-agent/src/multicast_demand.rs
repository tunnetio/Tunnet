//! Host multicast capability, driven by live discovery - not by VPN uptime.
//!
//! iroh attaches `MdnsAddressLookup` at endpoint construction. While that
//! lookup (or LAN mDNS service relay) is running, the embedder must hold the
//! platform multicast resource. Desktop has no host; [`set_needed`] is then a
//! no-op besides the process flag.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwapOption;

/// Platform owner of multicast reception (Android: `WifiManager.MulticastLock`).
pub trait MulticastHost: Send + Sync {
    fn set_held(&self, held: bool);
}

struct BoundHost {
    epoch: u64,
    inner: Box<dyn MulticastHost>,
}

impl MulticastHost for BoundHost {
    fn set_held(&self, held: bool) {
        if EPOCH.load(Ordering::SeqCst) != self.epoch {
            return;
        }
        self.inner.set_held(held);
    }
}

static HOST: ArcSwapOption<BoundHost> = ArcSwapOption::const_empty();
static EPOCH: AtomicU64 = AtomicU64::new(0);
static NEEDED: AtomicBool = AtomicBool::new(false);

/// Install the platform bridge. Releases any previous host, then reapplies
/// the current demand so a recreated Service picks up a live mesh.
pub fn set_multicast_host(host: Box<dyn MulticastHost>) {
    release_current_host();
    let epoch = EPOCH.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    HOST.store(Some(Arc::new(BoundHost { epoch, inner: host })));
    apply();
}

/// Drop the bridge so a destroyed Service cannot keep or re-acquire the lock.
pub fn clear_multicast_host() {
    release_current_host();
}

fn release_current_host() {
    let previous = HOST.swap(None);
    EPOCH.fetch_add(1, Ordering::SeqCst);
    if let Some(host) = previous {
        host.inner.set_held(false);
    }
}

pub fn multicast_needed() -> bool {
    NEEDED.load(Ordering::SeqCst)
}

pub(crate) fn set_needed(needed: bool) {
    NEEDED.store(needed, Ordering::SeqCst);
    apply();
}

fn apply() {
    if let Some(host) = HOST.load_full() {
        host.set_held(NEEDED.load(Ordering::SeqCst));
    }
}

/// Held for the lifetime of a mesh that needs local multicast discovery.
/// Dropping always clears demand, including on start-mesh failure unwind.
pub struct MulticastLease {
    active: bool,
}

impl MulticastLease {
    pub fn request(needed: bool) -> Self {
        set_needed(needed);
        Self { active: needed }
    }
}

impl Drop for MulticastLease {
    fn drop(&mut self) {
        if self.active {
            set_needed(false);
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone)]
    struct Fake {
        calls: Arc<Mutex<Vec<bool>>>,
    }

    impl MulticastHost for Fake {
        fn set_held(&self, held: bool) {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(held);
        }
    }

    fn reset() {
        clear_multicast_host();
        NEEDED.store(false, Ordering::SeqCst);
    }

    fn held_log(calls: &Arc<Mutex<Vec<bool>>>) -> Vec<bool> {
        calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    #[test]
    fn discovery_requests_multicast() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        let _lease = MulticastLease::request(true);
        assert!(multicast_needed());
        assert_eq!(held_log(&calls).last().copied(), Some(true));
        reset();
    }

    #[test]
    fn discovery_stop_releases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        {
            let _lease = MulticastLease::request(true);
        }
        assert!(!multicast_needed());
        let recorded = held_log(&calls);
        assert!(recorded.contains(&true));
        assert_eq!(recorded.last().copied(), Some(false));
        reset();
    }

    #[test]
    fn duplicate_acquire_is_idempotent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        set_needed(true);
        set_needed(true);
        assert_eq!(held_log(&calls).last().copied(), Some(true));
        reset();
    }

    #[test]
    fn duplicate_release_is_harmless() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        set_needed(false);
        set_needed(false);
        assert!(!held_log(&calls).contains(&true));
        reset();
    }

    #[test]
    fn discovery_disabled_from_startup_never_acquires() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        let _lease = MulticastLease::request(false);
        assert!(!multicast_needed());
        assert!(!held_log(&calls).contains(&true));
        reset();
    }

    #[test]
    fn runtime_shutdown_while_active_releases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        drop(MulticastLease::request(true));
        assert!(!multicast_needed());
        reset();
    }

    #[test]
    fn clear_host_releases_and_cannot_reacquire() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        set_needed(true);
        let stale = HOST.load_full().expect("bound");
        clear_multicast_host();
        let after_clear = held_log(&calls);
        assert!(after_clear.contains(&true));
        assert_eq!(after_clear.last().copied(), Some(false));
        stale.set_held(true);
        assert_eq!(held_log(&calls), after_clear);
        reset();
    }

    #[test]
    fn rebind_applies_existing_demand_to_the_new_host() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let first = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: first.clone(),
        }));
        set_needed(true);
        let second = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: second.clone(),
        }));
        assert_eq!(held_log(&first).last().copied(), Some(false));
        assert_eq!(held_log(&second).last().copied(), Some(true));
        reset();
    }

    #[test]
    fn replaced_host_rejects_stale_set_held() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let first = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: first.clone(),
        }));
        let stale = HOST.load_full().expect("bound");
        let second = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: second.clone(),
        }));
        let second_after_bind = held_log(&second);
        stale.set_held(true);
        assert!(!held_log(&first).contains(&true));
        assert_eq!(held_log(&second), second_after_bind);
        reset();
    }

    #[test]
    fn demand_without_a_host_is_remembered() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        set_needed(true);
        assert!(multicast_needed());
        let calls = Arc::new(Mutex::new(Vec::new()));
        set_multicast_host(Box::new(Fake {
            calls: calls.clone(),
        }));
        assert_eq!(&*calls.lock().unwrap_or_else(|e| e.into_inner()), &[true]);
        reset();
    }
}
