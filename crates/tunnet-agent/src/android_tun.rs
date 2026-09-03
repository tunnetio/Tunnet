//! Android TUN establishment, inverted: the agent asks the app for a device.
//!
//! Desktop platforms open the TUN themselves. Android cannot: only the
//! framework may do so, via `VpnService.Builder.establish()`, which lives on the
//! JVM side. The parameters, however, are known only to the agent, and only
//! once the node has bootstrapped (`runtime.rs` computes them just before
//! `build_tun`).
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

use anyhow::{Context, bail};
use arc_swap::ArcSwapOption;

/// What the app must configure on `VpnService.Builder` before `establish()`.
#[derive(Debug, Clone, Copy)]
pub struct TunRequest {
    /// Mesh address for this node, from `VpnService.Builder.addAddress`.
    pub ipv4: Ipv4Addr,
    /// Prefix length of the mesh CIDR. Direct mode uses /10, so the app should
    /// route the truncated network (`10.0.0.0/10`), not a host route.
    pub prefix: u8,
    /// Tunnel MTU, from `VpnService.Builder.setMtu`.
    pub mtu: u16,
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

static PROVIDER: ArcSwapOption<Box<dyn TunProvider>> = ArcSwapOption::const_empty();

/// Install the platform bridge. Must happen before the agent starts.
pub fn set_provider(provider: Box<dyn TunProvider>) {
    PROVIDER.store(Some(Arc::new(provider)));
}

/// Remove the bridge so a stopped agent cannot establish a new tunnel.
pub fn clear_provider() {
    PROVIDER.store(None);
}

/// Ask the app for a tunnel descriptor.
pub fn establish(request: TunRequest) -> anyhow::Result<OwnedFd> {
    let Some(provider) = PROVIDER.load_full() else {
        bail!("no TunProvider installed; the VpnService must register one before starting");
    };
    let fd = provider
        .establish(request)
        .context("VpnService.Builder.establish() failed")?;
    tracing::info!(
        ipv4 = %request.ipv4,
        prefix = request.prefix,
        mtu = request.mtu,
        "TUN established by VpnService"
    );
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
            ipv4: Ipv4Addr::new(10, 1, 2, 3),
            prefix: 10,
            mtu: 1280,
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
}
