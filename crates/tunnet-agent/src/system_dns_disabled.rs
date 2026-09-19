//! Host OS DNS overlay is compiled out (`host-dns` off).
//!
//! In-TUN PeerDNS still runs; the OS resolver is left alone. Used by
//! `tunnet-mobile`, which does not enable `host-dns`.

use std::net::Ipv4Addr;

pub struct DnsController;

impl DnsController {
    pub fn restore(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        false
    }

    pub fn apply(&self, _: &str, _: Ipv4Addr, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
