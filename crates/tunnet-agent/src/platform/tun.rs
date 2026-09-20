//! Android TUN establishment, inverted: the agent asks the app for a device.
//!
//! Desktop platforms open the TUN themselves. Android cannot: only the
//! framework may do so, via `VpnService.Builder.establish()`, which lives on the
//! JVM side. The parameters, however, are known only to the agent, and only
//! once the node has bootstrapped.
//!
//! So the dependency runs agent -> app, not app -> agent: the embedder installs
//! a [`TunProvider`] and the data plane calls it whenever it needs a device.
//! This also covers reconnects, where each `down`/`up` cycle must establish a
//! *fresh* session; a cached descriptor would refer to a revoked tunnel and
//! fail writes silently.
//!
//! Keeping this a trait keeps JNI out of the agent: `tunnet-mobile` owns the
//! JVM call, and tests can install a fake.

use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use arc_swap::ArcSwapOption;
use ipnet::Ipv4Net;

/// What the app must configure on `VpnService.Builder` before `establish()`.
///
/// Addresses and routes are separate lists because they are separate facts.
/// A node holds one `/32` per Direct network it belongs to, while the traffic
/// that must enter the tunnel is each network's whole peer range. Deriving one
/// from the other is what broke when addressing moved to exact `/32`s: a route
/// computed from the address prefix is a host route to the node itself, so no
/// peer traffic is captured and the tunnel silently carries nothing.
///
/// IPv6 passthrough and metered inheritance are agent policy. The host applies
/// them mechanically.
#[derive(Debug, Clone)]
pub struct TunRequest {
    /// Mesh addresses for this node, one per joined network, each applied with
    /// `VpnService.Builder.addAddress(addr, 32)`.
    pub addrs: Vec<Ipv4Addr>,
    /// Destinations to capture, from `VpnService.Builder.addRoute`. These are
    /// the joined networks' peer ranges plus the in-TUN DNS host route, not
    /// anything derived from `addrs`, and never a default route. iroh
    /// relay/direct underlay therefore stays on the OS table.
    pub routes: Vec<Ipv4Net>,
    /// Resolvers to advertise, from `VpnService.Builder.addDnsServer`.
    ///
    /// These must be reachable through the tunnel. PeerDNS answers on
    /// [`tunnet_common::VirtualResolverEndpoint`] inside the TUN.
    pub dns: Vec<Ipv4Addr>,
    /// Tunnel MTU, from `VpnService.Builder.setMtu`.
    pub mtu: u16,
    /// `VpnService.Builder.allowFamily(AF_INET6)` so IPv6 stays on the underlay
    /// while Tunnet is IPv4-only.
    pub allow_ipv6_passthrough: bool,
    /// `setMetered(false)`: inherit the underlying network's metered state.
    pub inherit_underlying_metered: bool,
}

/// Bridge to the platform VPN API. Implemented by the embedding app.
pub trait TunProvider: Send + Sync {
    /// Establish a tunnel and transfer descriptor ownership to the caller.
    ///
    /// Implementations must yield an owned descriptor: on Android that means
    /// `ParcelFileDescriptor.detachFd()`, never `getFd()`, since the returned
    /// descriptor is closed when the device is dropped.
    fn establish(&self, request: TunRequest) -> anyhow::Result<OwnedFd>;
}

struct BoundProvider {
    epoch: u64,
    inner: Box<dyn TunProvider>,
}

impl TunProvider for BoundProvider {
    fn establish(&self, request: TunRequest) -> anyhow::Result<OwnedFd> {
        if EPOCH.load(Ordering::SeqCst) != self.epoch {
            bail!("TunProvider was replaced; this Service is no longer the host");
        }
        self.inner.establish(request)
    }
}

static PROVIDER: ArcSwapOption<BoundProvider> = ArcSwapOption::const_empty();
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Install the platform bridge. Replaces any previous provider.
pub fn set_provider(provider: Box<dyn TunProvider>) {
    let epoch = EPOCH.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    PROVIDER.store(Some(Arc::new(BoundProvider {
        epoch,
        inner: provider,
    })));
}

/// Drop the bridge so a destroyed Service cannot establish a new tunnel.
///
/// Does not stop the agent. A later [`set_provider`] rebinds a new host.
pub fn clear_provider() {
    EPOCH.fetch_add(1, Ordering::SeqCst);
    PROVIDER.store(None);
}

/// Ask the app for a tunnel descriptor.
pub fn establish(request: TunRequest) -> anyhow::Result<OwnedFd> {
    let Some(provider) = PROVIDER.load_full() else {
        bail!("no TunProvider installed; the VpnService must register one before starting");
    };
    let summary = format!(
        "addrs={:?} routes={:?} dns={:?} mtu={} ipv6_passthrough={} inherit_metered={}",
        request.addrs,
        request.routes,
        request.dns,
        request.mtu,
        request.allow_ipv6_passthrough,
        request.inherit_underlying_metered
    );
    let fd = provider
        .establish(request)
        .context("VpnService.Builder.establish() failed")?;
    tracing::info!(%summary, "TUN established by VpnService");
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::Mutex;

    /// The provider is process-wide, so tests must not run concurrently against
    /// it. Poisoning is irrelevant here: a panicking test leaves no shared state
    /// worth protecting, so recover the guard instead of cascading failures.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Fake;
    impl TunProvider for Fake {
        fn establish(&self, _request: TunRequest) -> anyhow::Result<OwnedFd> {
            // A pipe read end stands in for a tunnel descriptor.
            let mut fds = [0i32; 2];
            // SAFETY: pipe() writes exactly two descriptors into the array.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                bail!("pipe failed");
            }
            // SAFETY: fds[1] is closed here, fds[0] ownership moves to caller.
            unsafe { libc::close(fds[1]) };
            Ok(unsafe { OwnedFd::from_raw_fd(fds[0]) })
        }
    }

    fn request() -> TunRequest {
        TunRequest {
            addrs: vec![Ipv4Addr::new(10, 1, 2, 3)],
            routes: vec!["10.1.0.0/16".parse().unwrap()],
            dns: vec![tunnet_common::VirtualResolverEndpoint::IP],
            mtu: 1280,
            allow_ipv6_passthrough: true,
            inherit_underlying_metered: true,
        }
    }

    #[test]
    fn establishing_without_a_provider_is_an_error() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_provider();
        let err = establish(request()).unwrap_err().to_string();
        assert!(err.contains("no TunProvider"), "{err}");
    }

    #[test]
    fn installed_provider_yields_an_owned_descriptor() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_provider(Box::new(Fake));
        let fd = establish(request()).expect("provider should supply a descriptor");
        assert!(fd.as_raw_fd() >= 0);
        clear_provider();
    }

    #[test]
    fn replaced_provider_cannot_establish() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_provider(Box::new(Fake));
        let old = PROVIDER.load_full().expect("bound");
        set_provider(Box::new(Fake));
        let err = old.establish(request()).unwrap_err().to_string();
        assert!(err.contains("replaced"), "{err}");
        establish(request()).expect("new provider works");
        clear_provider();
    }

    #[test]
    fn clear_provider_invalidates_a_held_handle() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_provider(Box::new(Fake));
        let old = PROVIDER.load_full().expect("bound");
        clear_provider();
        let err = old.establish(request()).unwrap_err().to_string();
        assert!(err.contains("replaced"), "{err}");
        let err = establish(request()).unwrap_err().to_string();
        assert!(err.contains("no TunProvider"), "{err}");
    }
}
