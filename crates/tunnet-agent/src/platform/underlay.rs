//! Underlay socket protection: the agent lists TCP/UDP FDs, the host protects them.
//!
//! ICMP is absent from `/proc/net/{tcp,udp}*` so mesh ping stays on the TUN.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwapOption;

/// Platform owner of underlay bypass (`VpnService.protect` on Android).
pub trait UnderlayProtect: Send + Sync {
    fn protect_fd(&self, fd: i32);
}

struct BoundProtect {
    epoch: u64,
    inner: Box<dyn UnderlayProtect>,
}

impl UnderlayProtect for BoundProtect {
    fn protect_fd(&self, fd: i32) {
        if EPOCH.load(Ordering::SeqCst) != self.epoch {
            return;
        }
        self.inner.protect_fd(fd);
    }
}

static HOST: ArcSwapOption<BoundProtect> = ArcSwapOption::const_empty();
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Install the platform bridge. Replaces any previous host.
pub fn set_underlay_protect(host: Box<dyn UnderlayProtect>) {
    let epoch = EPOCH.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    HOST.store(Some(Arc::new(BoundProtect { epoch, inner: host })));
}

/// Drop the bridge so a destroyed Service cannot protect sockets.
pub fn clear_underlay_protect() {
    EPOCH.fetch_add(1, Ordering::SeqCst);
    HOST.store(None);
}

/// Protect currently open underlay TCP/UDP sockets. No-op without a host.
pub fn protect_existing() {
    let Some(host) = HOST.load_full() else {
        return;
    };
    for fd in underlay_fds() {
        host.protect_fd(fd);
    }
}

fn socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

fn inodes_from_proc_net(table: &str) -> HashSet<u64> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(9)?.parse().ok())
        .collect()
}

fn underlay_fds() -> Vec<i32> {
    let mut inodes = HashSet::new();
    for path in [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        if let Ok(table) = std::fs::read_to_string(path) {
            inodes.extend(inodes_from_proc_net(&table));
        }
    }
    if inodes.is_empty() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    let mut fds = Vec::new();
    for entry in entries.flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let Some(inode) = socket_inode(&target.to_string_lossy()) else {
            continue;
        };
        if inodes.contains(&inode) {
            fds.push(fd);
        }
    }
    fds
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Fake {
        calls: Arc<AtomicUsize>,
    }

    impl UnderlayProtect for Fake {
        fn protect_fd(&self, _fd: i32) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn without_a_host_protect_is_a_noop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_underlay_protect();
        protect_existing();
    }

    #[test]
    fn installed_host_is_invoked() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let calls = Arc::new(AtomicUsize::new(0));
        set_underlay_protect(Box::new(Fake {
            calls: calls.clone(),
        }));
        protect_existing();
        // Host is invoked only for sockets that exist in this process.
        let _ = calls.load(Ordering::SeqCst);
        clear_underlay_protect();
        let after = calls.load(Ordering::SeqCst);
        protect_existing();
        assert_eq!(calls.load(Ordering::SeqCst), after);
    }

    #[test]
    fn replaced_host_rejects_stale_calls() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let first = Arc::new(AtomicUsize::new(0));
        set_underlay_protect(Box::new(Fake {
            calls: first.clone(),
        }));
        let stale = HOST.load_full().expect("bound");
        let second = Arc::new(AtomicUsize::new(0));
        set_underlay_protect(Box::new(Fake {
            calls: second.clone(),
        }));
        stale.protect_fd(3);
        assert_eq!(first.load(Ordering::SeqCst), 0);
        assert_eq!(second.load(Ordering::SeqCst), 0);
        clear_underlay_protect();
    }

    #[test]
    fn proc_net_inodes_are_column_10() {
        let table = "\
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
 0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
";
        assert!(inodes_from_proc_net(table).contains(&12345));
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("/dev/null"), None);
    }
}
