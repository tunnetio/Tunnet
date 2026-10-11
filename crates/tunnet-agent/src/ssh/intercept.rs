//! Mesh-local TCP/22 interception for the embedded SSH listener.
//!
//! Only packets whose IPv4 address is an active embedded-SSH binding are
//! rewritten. Routed/subnet destinations and networks with SSH disabled are
//! left alone so native sshd can own ordinary TCP/22.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;

pub const SSH_INTERNAL_PORT: u16 = 30022;

#[derive(Clone)]
pub struct SshIntercept {
    addrs: Arc<ArcSwap<HashSet<Ipv4Addr>>>,
}

impl SshIntercept {
    pub fn new() -> Self {
        Self {
            addrs: Arc::new(ArcSwap::from_pointee(HashSet::new())),
        }
    }

    pub fn set(&self, addrs: HashSet<Ipv4Addr>) {
        self.addrs.store(Arc::new(addrs));
    }

    pub fn snapshot(&self) -> HashSet<Ipv4Addr> {
        self.addrs.load().as_ref().clone()
    }
}

impl Default for SshIntercept {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_tracks_enabled_addresses() {
        let ip = Ipv4Addr::new(10, 110, 66, 1);
        let table = SshIntercept::new();
        table.set([ip].into_iter().collect());
        assert_eq!(table.snapshot(), [ip].into_iter().collect());
    }
}
