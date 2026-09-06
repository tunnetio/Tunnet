//! OS DNS integration for PeerDNS, implemented with [`osdns`].
//!
//! Tunnet owns DNS *product policy* here; `osdns` owns capability/semantic
//! validation, interface resolution, native resource identity, transactions,
//! journaling, crash recovery, Enforce observation, reconciliation, rollback,
//! restoration, and all platform-specific behavior.
//!
//! Lifecycle (blocking control-plane calls; invoke via
//! `tokio::task::spawn_blocking` from async code):
//!
//! ```text
//! DnsController::create()                    // manager + stale recovery
//!        ↓
//! capture underlay upstream (PeerDNS start, before overlay)
//!        ↓
//! apply(ifname, resolver_ip, suffix)            // apply → hold Lease
//!        ↓
//! update(...) on change                      // Lease::update (transactional)
//!        ↓
//! restore() on dataplane stop/shutdown       // explicit; abandon on conflict
//! ```
//!
//! `ConflictPolicy::Enforce` is self-contained: osdns starts its own internal
//! native observation once an active lease exists, so Tunnet holds no public
//! watcher. If the TUN interface is destroyed and recreated — even under the
//! same name with a different native identity — [`Lease::update`] reports
//! `Error::UpdateRequiresRebind` and the old lease is safely ended before a
//! fresh one is applied.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use osdns::{
    Capabilities, ConflictPolicy, DnsConfig, DnsManager, DnsScope, InterfaceSelector, Lease,
    RecoveryOutcome, RestoreFailure,
};

/// Owner tag for every lease, journal record, and platform ownership marker.
pub const OWNER: &str = "io.tunnet.agent";

/// Tunnet's DNS product-policy holder: one long-lived [`DnsManager`] and at
/// most one active [`Lease`].
///
/// This is intentionally not a wrapper around `osdns`: it contains only
/// Tunnet-specific policy (PeerDNS IP, DNS suffix, target TUN name,
/// split/full fallback choice). Everything below `osdns::DnsConfig` —
/// validation, interface resolution, transactions, Enforce observation,
/// reconciliation, restoration — is owned by `osdns`.
pub struct DnsController {
    manager: DnsManager,
    state: parking_lot::Mutex<State>,
}

struct State {
    lease: Option<Lease>,
}

impl DnsController {
    /// Build the agent's long-lived DNS integration: manager (Enforce) plus
    /// stale-journal recovery and capability logging.
    ///
    /// Blocking; call via `spawn_blocking` from async code. Enforce needs no
    /// public watcher from Tunnet: osdns observes natively once a lease is
    /// active, and returns typed `Unsupported` where Enforce is unavailable.
    pub fn create() -> osdns::Result<Arc<Self>> {
        Self::wrap(
            DnsManager::builder()
                .owner(OWNER)
                .conflict_policy(ConflictPolicy::Enforce)
                .build()?,
        )
    }

    /// Shared initialization for production managers and
    /// `osdns::testing` fake-backend managers.
    pub fn wrap(manager: DnsManager) -> osdns::Result<Arc<Self>> {
        recover_stale(&manager)?;
        match manager.capabilities() {
            Ok(caps) => tracing::info!(
                backend = %caps.backend,
                read = caps.read,
                global_dns = caps.global_dns,
                per_interface_dns = caps.per_interface_dns,
                split_dns = caps.split_dns,
                default_route = caps.default_route,
                watch = caps.watch,
                cache_flush = caps.cache_flush,
                "osdns DNS integration enabled"
            ),
            Err(e) => tracing::warn!(error = %e, "osdns capabilities unavailable"),
        }
        Ok(Arc::new(Self {
            manager,
            state: parking_lot::Mutex::new(State { lease: None }),
        }))
    }

    /// Whether a PeerDNS lease is currently held.
    pub fn is_active(&self) -> bool {
        self.state.lock().lease.is_some()
    }

    /// Apply the PeerDNS overlay (apply → hold lease).
    /// Delegates to [`DnsController::update`] when a lease already exists.
    ///
    /// Blocking; call via `spawn_blocking`. On failure nothing is mutated
    /// that was not already ours, and [`DnsController::is_active`] stays
    /// `false` so callers never claim PeerDNS is active without the overlay.
    pub fn apply(&self, ifname: &str, resolver_ip: Ipv4Addr, suffix: &str) -> osdns::Result<()> {
        if self.state.lock().lease.is_some() {
            return self.update(ifname, resolver_ip, suffix);
        }
        self.apply_fresh(ifname, resolver_ip, suffix)
    }

    /// Move to the current desired configuration.
    ///
    /// With a live lease this is one transactional [`Lease::update`] across
    /// all owned resources: DNS IP changes, suffix changes, TUN renames, and
    /// TUN recreations that keep the same name but change the native identity
    /// (ifindex, GUID, service UUID) are all detected by osdns itself. When
    /// the update resolves to a different resource set, osdns reports
    /// `Error::UpdateRequiresRebind` and the old lease is safely ended before
    /// a fresh one is applied — Tunnet never predicts the resource set.
    ///
    /// Blocking; call via `spawn_blocking`.
    pub fn update(&self, ifname: &str, resolver_ip: Ipv4Addr, suffix: &str) -> osdns::Result<()> {
        if self.state.lock().lease.is_none() {
            return self.apply_fresh(ifname, resolver_ip, suffix);
        }
        let caps = self.manager.capabilities()?;
        let config = desired_config(&caps, tun_selector(ifname), resolver_ip, suffix)?;
        // `apply`/`update` validate again before mutation, so no separate
        // preflight is needed here: osdns guarantees every explicitly
        // requested semantic is representable when these succeed.
        let result = {
            let state = self.state.lock();
            let lease = state.lease.as_ref().expect("checked above");
            lease.update(&config)
        };
        match result {
            Ok(()) => {
                tracing::info!(%resolver_ip, suffix, ifname, "PeerDNS lease updated");
                self.flush_cache_best_effort();
                Ok(())
            }
            Err(osdns::Error::UpdateRequiresRebind { owned, requested }) => {
                tracing::info!(
                    ?owned,
                    ?requested,
                    "DNS resource ownership changed; ending old lease for a fresh one"
                );
                self.restore()?;
                self.apply_fresh(ifname, resolver_ip, suffix)
            }
            Err(e) => {
                tracing::error!(error = %e, "PeerDNS lease update failed");
                Err(e)
            }
        }
    }

    /// Explicit restoration (the normal shutdown path; do not rely on `Drop`).
    ///
    /// On external modification the foreign state wins: the lease is
    /// abandoned without mutating the system, per `osdns` semantics. Other
    /// failures keep the lease so the caller can retry.
    ///
    /// Blocking; call via `spawn_blocking`.
    pub fn restore(&self) -> osdns::Result<()> {
        let lease = self.state.lock().lease.take();
        let Some(lease) = lease else { return Ok(()) };
        match lease.restore() {
            Ok(()) => {
                tracing::info!("PeerDNS lease restored");
                self.flush_cache_best_effort();
                Ok(())
            }
            Err(failure) if failure.error.is_external_modification() => {
                tracing::warn!(
                    error = %failure.error,
                    "OS DNS changed externally; leaving external state untouched"
                );
                if let Err(e) = failure.lease.abandon() {
                    tracing::warn!(error = %e, "abandoning conflicted DNS lease failed");
                }
                Ok(())
            }
            Err(failure) => {
                tracing::error!(error = %failure.error, "PeerDNS lease restore failed");
                let RestoreFailure { error, lease } = failure;
                self.state.lock().lease = Some(lease);
                Err(error)
            }
        }
    }

    fn apply_fresh(&self, ifname: &str, resolver_ip: Ipv4Addr, suffix: &str) -> osdns::Result<()> {
        let caps = self.manager.capabilities()?;
        let config = desired_config(&caps, tun_selector(ifname), resolver_ip, suffix)?;
        match self.manager.apply(&config) {
            Ok(lease) => {
                if lease.is_noop() {
                    tracing::info!(
                        %resolver_ip,
                        suffix,
                        ifname,
                        "PeerDNS DNS already in effect; no-op lease"
                    );
                } else {
                    tracing::info!(
                        %resolver_ip,
                        suffix,
                        ifname,
                        backend = %caps.backend,
                        split = caps.split_dns,
                        "PeerDNS lease applied"
                    );
                }
                self.state.lock().lease = Some(lease);
                self.flush_cache_best_effort();
                Ok(())
            }
            Err(e) => {
                log_apply_failure(&e);
                Err(e)
            }
        }
    }

    fn flush_cache_best_effort(&self) {
        let caps = match self.manager.capabilities() {
            Ok(caps) => caps,
            Err(_) => return,
        };
        if !caps.cache_flush {
            return;
        }
        if let Err(e) = self.manager.flush_cache() {
            tracing::warn!(error = %e, "osdns DNS cache flush failed");
        }
    }
}

/// Tunnet's product identity for its TUN interface: "use this interface".
/// `osdns` resolves the name to the backend's stable native identity (Linux
/// ifindex, Windows GUID, macOS service UUID) at apply/update time, and the
/// lease owns that identity — so Tunnet never resolves OS identity itself.
fn tun_selector(ifname: &str) -> InterfaceSelector {
    InterfaceSelector::Name(OsString::from(ifname))
}

/// Tunnet's capability-driven DNS strategy.
///
/// Preferred order: per-interface PeerDNS + routing domain (split DNS, so
/// only Tunnet suffixes go to PeerDNS) → broader per-interface/global
/// PeerDNS fallback, where PeerDNS resolves Tunnet names internally and
/// external names through Hickory → explicit unsupported error. Product
/// policy only; `osdns` translates the result into systemd-resolved /
/// NetworkManager / resolvconf / IP Helper + NRPT / SystemConfiguration
/// mechanics and validates that every requested semantic is representable.
pub fn desired_config(
    caps: &Capabilities,
    selector: InterfaceSelector,
    nameserver: Ipv4Addr,
    suffix: &str,
) -> osdns::Result<DnsConfig> {
    let nameserver = IpAddr::V4(nameserver);
    if caps.per_interface_dns && caps.split_dns {
        let mut builder = DnsConfig::builder(DnsScope::Interface(selector))
            .nameserver(nameserver)
            .routing_domain(suffix);
        // Explicit default-route control is itself a capability
        // (NetworkManager-style backends expose routing domains without it).
        // `None` means preserve/unspecified — never fake `false`.
        if caps.default_route {
            builder = builder.default_route(false);
        }
        return builder.build();
    }
    if caps.per_interface_dns {
        tracing::warn!(
            "split DNS unavailable; routing all relevant DNS through PeerDNS (Hickory forwards external names)"
        );
        return DnsConfig::builder(DnsScope::Interface(selector))
            .nameserver(nameserver)
            .build();
    }
    if caps.global_dns {
        tracing::warn!(
            "per-interface DNS unavailable; routing system DNS through PeerDNS (Hickory forwards external names)"
        );
        return DnsConfig::builder(DnsScope::Global)
            .nameserver(nameserver)
            .build();
    }
    Err(osdns::Error::Unsupported {
        backend: caps.backend,
        reason: "backend supports neither per-interface nor global DNS".into(),
    })
}

/// Agent-startup crash recovery: let `osdns` inspect its durable journal and
/// safely recover stale ownership from a crashed daemon process.
///
/// Never guesses ownership: external conflicts are surfaced and left
/// untouched rather than blindly restoring old DNS state. Corrupt journals
/// fail closed.
fn recover_stale(manager: &DnsManager) -> osdns::Result<()> {
    match manager.recover_stale() {
        Ok(outcomes) => {
            for outcome in outcomes {
                match outcome {
                    RecoveryOutcome::Restored { resource, lease_id } => {
                        tracing::info!(?resource, %lease_id, "recovered stale DNS transaction")
                    }
                    RecoveryOutcome::JournalCleared { resource, lease_id } => {
                        tracing::info!(?resource, %lease_id, "cleared stale DNS journal")
                    }
                    RecoveryOutcome::ExternalConflict { resource, lease_id } => {
                        tracing::error!(
                            ?resource,
                            %lease_id,
                            "stale DNS transaction conflicts with external state; left untouched"
                        )
                    }
                    RecoveryOutcome::Busy { resource } => {
                        tracing::warn!(?resource, "stale DNS resource busy; left untouched")
                    }
                    _ => tracing::debug!("unrecognized DNS recovery outcome"),
                }
            }
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "DNS journal recovery failed; failing closed");
            Err(e)
        }
    }
}

fn log_apply_failure(e: &osdns::Error) {
    match e {
        osdns::Error::RequiresPrivilege(_) => {
            tracing::error!(error = %e, "PeerDNS OS configuration needs elevated privileges")
        }
        osdns::Error::Unsupported { .. } => {
            tracing::error!(error = %e, "PeerDNS OS configuration unsupported on this backend")
        }
        _ => tracing::error!(error = %e, "PeerDNS OS configuration failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osdns::BackendKind;

    fn split_caps() -> Capabilities {
        Capabilities::new(BackendKind::Fake)
            .with_per_interface_dns(true)
            .with_split_dns(true)
            .with_default_route(true)
    }

    /// NetworkManager-like: routing domains without explicit
    /// default-route control. Enforce needs change notifications, so
    /// `watch` stays on: these caps model a restricted *DNS* backend,
    /// not a missing observer.
    fn split_caps_no_default_route() -> Capabilities {
        Capabilities::new(BackendKind::Fake)
            .with_per_interface_dns(true)
            .with_split_dns(true)
            .with_watch(true)
    }

    fn selector() -> InterfaceSelector {
        InterfaceSelector::Name(OsString::from("tunnet0"))
    }

    #[test]
    fn split_with_default_route_cap_uses_explicit_no_default_route() {
        let config = desired_config(
            &split_caps(),
            selector(),
            Ipv4Addr::new(127, 0, 0, 1),
            "tunnet",
        )
        .unwrap();
        assert_eq!(config.nameservers(), &[IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(config.routing_domains().len(), 1);
        assert!(
            format!("{:?}", config.routing_domains()).contains("tunnet"),
            "routing domain should carry the Tunnet suffix"
        );
        assert_eq!(config.default_route(), Some(false));
        assert_eq!(
            *config.scope(),
            DnsScope::Interface(InterfaceSelector::Name(OsString::from("tunnet0")))
        );
    }

    #[test]
    fn split_without_default_route_cap_preserves_unspecified() {
        let config = desired_config(
            &split_caps_no_default_route(),
            selector(),
            Ipv4Addr::new(127, 0, 0, 1),
            "tunnet",
        )
        .unwrap();
        assert_eq!(config.nameservers(), &[IpAddr::from([127, 0, 0, 1])]);
        assert_eq!(config.routing_domains().len(), 1);
        // Never fake `false`: None means preserve/unspecified.
        assert_eq!(config.default_route(), None);
    }

    #[test]
    fn multiple_routing_domains_preserved_when_supported() {
        let config = DnsConfig::builder(DnsScope::Interface(selector()))
            .nameserver(IpAddr::from([127, 0, 0, 1]))
            .routing_domain("tunnet")
            .routing_domain("office.tunnet")
            .default_route(false)
            .build()
            .unwrap();
        assert_eq!(config.routing_domains().len(), 2);
    }

    #[test]
    fn backend_without_split_dns_uses_full_peerdns_fallback() {
        let caps = Capabilities::new(BackendKind::Fake).with_per_interface_dns(true);
        let config =
            desired_config(&caps, selector(), Ipv4Addr::new(127, 0, 0, 1), "tunnet").unwrap();
        assert!(config.routing_domains().is_empty());
        assert_eq!(config.nameservers(), &[IpAddr::from([127, 0, 0, 1])]);
        assert!(matches!(config.scope(), DnsScope::Interface(_)));
    }

    #[test]
    fn global_only_backend_uses_global_fallback() {
        let caps = Capabilities::new(BackendKind::Fake).with_global_dns(true);
        let config =
            desired_config(&caps, selector(), Ipv4Addr::new(127, 0, 0, 1), "tunnet").unwrap();
        assert_eq!(*config.scope(), DnsScope::Global);
        assert_eq!(config.nameservers(), &[IpAddr::from([127, 0, 0, 1])]);
    }

    #[test]
    fn unsupported_capability_combination_fails_clearly() {
        let caps = Capabilities::new(BackendKind::Fake);
        let err = desired_config(&caps, selector(), Ipv4Addr::new(127, 0, 0, 1), "tunnet")
            .expect_err("backend with no DNS scope must fail");
        assert!(matches!(err, osdns::Error::Unsupported { .. }));
    }

    #[test]
    fn configurable_interface_name_is_respected() {
        let config = desired_config(
            &split_caps(),
            InterfaceSelector::Name(OsString::from("custom0")),
            Ipv4Addr::new(127, 0, 0, 1),
            "tunnet",
        )
        .unwrap();
        assert_eq!(
            *config.scope(),
            DnsScope::Interface(InterfaceSelector::Name(OsString::from("custom0")))
        );
    }

    mod backend_tests {
        use super::*;
        use osdns::ConflictPolicy;
        use osdns::testing::{FakeDns, FakeState, manager_for_testing_with_policy};
        use std::time::Duration;

        fn enforce_manager(caps: Capabilities) -> (DnsManager, FakeDns, tempfile::TempDir) {
            let dir = tempfile::tempdir().unwrap();
            let fake = FakeDns::with_capabilities(caps);
            let manager = manager_for_testing_with_policy(
                "io.tunnet.agent",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            (manager, fake, dir)
        }

        fn full_caps() -> Capabilities {
            Capabilities::new(BackendKind::Fake)
                .with_read(true)
                .with_per_interface_dns(true)
                .with_split_dns(true)
                .with_default_route(true)
                .with_global_dns(true)
                .with_watch(true)
                .with_cache_flush(true)
        }

        fn nm_like_caps() -> Capabilities {
            Capabilities::new(BackendKind::Fake)
                .with_read(true)
                .with_per_interface_dns(true)
                .with_split_dns(true)
                .with_watch(true)
        }

        // The fake backend exposes fixed interfaces `eth0` (index 1) and
        // `wlan1` (index 2); interface-scoped tests must target those.
        #[test]
        fn lease_lifecycle_apply_update_restore() {
            let (manager, fake, _dir) = enforce_manager(full_caps());
            let dns = DnsController::wrap(manager).unwrap();
            assert!(!dns.is_active());

            dns.apply("eth0", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .unwrap();
            assert!(dns.is_active());

            dns.update("eth0", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .unwrap();
            assert!(dns.is_active());

            dns.restore().unwrap();
            assert!(!dns.is_active());
            assert_eq!(
                fake.current_state("fake:interface:1").unwrap(),
                Some(FakeState::Empty)
            );

            // Restoring without a lease is a no-op success.
            dns.restore().unwrap();
        }

        #[test]
        fn tun_recreation_releases_old_lease_and_applies_new() {
            let (manager, fake, _dir) = enforce_manager(full_caps());
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .unwrap();

            // A different native identity resolves to a different resource
            // set; osdns reports it, Tunnet safely rebinds.
            dns.update("wlan1", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .unwrap();
            assert!(dns.is_active());
            assert_eq!(
                fake.current_state("fake:interface:1").unwrap(),
                Some(FakeState::Empty),
                "old TUN resource must be released"
            );
            assert!(matches!(
                fake.current_state("fake:interface:2").unwrap(),
                Some(FakeState::Configured { .. })
            ));

            dns.restore().unwrap();
            assert!(!dns.is_active());
        }

        #[test]
        fn invalid_config_is_not_a_rebind() {
            let (manager, fake, _dir) = enforce_manager(full_caps());
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();

            // A malformed suffix is a real configuration error: the lease
            // must be retained untouched, never restored + re-applied.
            // (Note: `""` parses as the root domain, so use an overlong
            // label to force a genuine `InvalidConfig`.)
            let bad_suffix = format!("{}.tunnet", "a".repeat(64));
            let err = dns
                .update("eth0", RESOLVER_IP, &bad_suffix)
                .expect_err("overlong label must fail");
            assert!(matches!(err, osdns::Error::InvalidConfig(_)));
            assert!(dns.is_active());
            let current = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert!(
                matches!(&current, FakeState::Configured { nameservers, .. }
                    if nameservers == &vec![IpAddr::V4(RESOLVER_IP)]),
                "previous configuration must be preserved, got {current:?}"
            );
        }

        #[test]
        fn routing_domain_change_rebinds_to_new_resources() {
            use osdns::testing::FakeDns;

            // Multi-resource shape (macOS-like): each routing domain owns an
            // additional scoped resource, so a suffix change alters the
            // owned resource set and forces UpdateRequiresRebind.
            let dir = tempfile::tempdir().unwrap();
            let fake = FakeDns::with_multi_resource(full_caps());
            let manager = manager_for_testing_with_policy(
                "io.tunnet.agent",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();

            dns.update("eth0", RESOLVER_IP, "office.tunnet").unwrap();
            assert!(dns.is_active());
            assert!(matches!(
                fake.current_state("fake:resolver:office.tunnet").unwrap(),
                Some(FakeState::Configured { .. })
            ));
            assert_eq!(
                fake.current_state("fake:resolver:tunnet").unwrap(),
                Some(FakeState::Empty),
                "previous scoped resource must be released"
            );

            dns.restore().unwrap();
            assert!(!dns.is_active());
        }

        #[test]
        fn failed_update_preserves_previous_complete_configuration() {
            use osdns::testing::FakeOp;

            let (manager, fake, _dir) = enforce_manager(full_caps());
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();

            // The transactional update fails mid-mutation...
            fake.inject_backend_failure(FakeOp::Apply, 1, "simulated OS failure");
            let err = dns
                .update("eth0", Ipv4Addr::new(100, 100, 100, 54), "tunnet")
                .expect_err("injected failure must fail");
            assert!(matches!(err, osdns::Error::Platform { .. }));
            // ...and the previous complete configuration is still in effect.
            assert!(dns.is_active());
            let current = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert!(
                matches!(&current, FakeState::Configured { nameservers, .. }
                    if nameservers == &vec![IpAddr::V4(RESOLVER_IP)]),
                "previous configuration must be preserved, got {current:?}"
            );
        }
        #[test]
        fn failed_apply_does_not_claim_dns_active() {
            let (manager, _fake, _dir) =
                enforce_manager(Capabilities::new(BackendKind::Fake).with_watch(true));
            let dns = DnsController::wrap(manager).unwrap();
            let err = dns
                .apply("tunnet0", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .expect_err("backend without DNS scopes must fail");
            assert!(matches!(err, osdns::Error::Unsupported { .. }));
            assert!(!dns.is_active());
        }

        #[test]
        fn fresh_state_recovery_is_empty_and_safe() {
            let (manager, _fake, _dir) = enforce_manager(full_caps());
            let outcomes = manager.recover_stale().unwrap();
            assert!(outcomes.is_empty());
            // A controller can still be built on recovered state.
            let dns = DnsController::wrap(manager).unwrap();
            assert!(!dns.is_active());
        }

        #[test]
        fn global_fallback_lifecycle_on_restricted_backend() {
            let caps = Capabilities::new(BackendKind::Fake)
                .with_read(true)
                .with_global_dns(true)
                .with_watch(true);
            let (manager, _fake, _dir) = enforce_manager(caps);
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("tunnet0", Ipv4Addr::new(127, 0, 0, 1), "tunnet")
                .unwrap();
            assert!(dns.is_active());
            dns.restore().unwrap();
            assert!(!dns.is_active());
        }

        #[test]
        fn verification_failure_does_not_claim_dns_active() {
            let (manager, fake, _dir) = enforce_manager(full_caps());
            let dns = DnsController::wrap(manager).unwrap();
            // Simulate an OS whose read-back disagrees with what was applied.
            fake.lie_once_on_readback(FakeState::Empty);
            let err = dns
                .apply("eth0", RESOLVER_IP, "tunnet")
                .expect_err("read-back mismatch must fail");
            assert!(matches!(err, osdns::Error::VerificationFailed { .. }));
            assert!(!dns.is_active());
        }

        #[test]
        fn split_without_default_route_control_applies_successfully() {
            let dir = tempfile::tempdir().unwrap();
            let fake = FakeDns::with_capabilities(nm_like_caps());
            let manager = manager_for_testing_with_policy(
                "io.tunnet.agent",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            let dns = DnsController::wrap(manager).unwrap();
            // An explicitly requested `default_route(false)` would be
            // rejected here; Tunnet leaves it unspecified instead.
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();
            assert!(dns.is_active());
            let current = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert!(
                matches!(
                    &current,
                    FakeState::Configured {
                        default_route: None,
                        ..
                    }
                ),
                "default route must stay unspecified, got {current:?}"
            );
            dns.restore().unwrap();
        }

        #[test]
        fn enforce_reconciles_external_change_and_restores_to_new_base() {
            use osdns::testing::DebugReconcile;

            let (manager, fake, _dir) = enforce_manager(full_caps());
            let probe = manager.clone();
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();

            // Enforce observation is internal to osdns: Tunnet holds no
            // public watch() subscription, yet the live lease is observed.
            assert!(probe.debug_enforce_refs() >= 1);
            probe.suspend_enforce_background();

            // An external actor (DHCP, admin, another VPN) rewrites our resource.
            fake.external_change("fake:interface:1", foreign_state())
                .unwrap();
            let outcome = probe.debug_reconcile("fake:interface:1").unwrap();
            assert_eq!(outcome, DebugReconcile::Rebased);

            // The Tunnet overlay is reapplied on top of the new external base.
            let current = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert!(
                matches!(&current, FakeState::Configured { nameservers, .. }
                    if nameservers.contains(&IpAddr::V4(RESOLVER_IP))),
                "overlay must be reapplied, got {current:?}"
            );

            // Restoring a rebased lease returns to the NEW external base,
            // not the stale pre-lease state.
            dns.restore().unwrap();
            let restored = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert!(
                matches!(&restored, FakeState::Configured { nameservers, .. }
                    if nameservers == &vec![FOREIGN_IP]),
                "restore must return to the rebased base, got {restored:?}"
            );
            assert!(!dns.is_active());
            assert_eq!(probe.debug_enforce_refs(), 0);
        }

        #[test]
        fn restore_conflict_abandons_and_preserves_external_state() {
            use osdns::testing::manager_for_testing;

            // Cooperative policy: no background reconciliation races this
            // test; the external modification must survive restore verbatim.
            let dir = tempfile::tempdir().unwrap();
            let fake = FakeDns::with_capabilities(full_caps());
            let manager =
                manager_for_testing("io.tunnet.agent", dir.path(), &fake, Duration::from_secs(5))
                    .unwrap();
            let dns = DnsController::wrap(manager).unwrap();
            dns.apply("eth0", RESOLVER_IP, "tunnet").unwrap();

            fake.external_change("fake:interface:1", foreign_state())
                .unwrap();
            // No reconciliation pass runs: restore must not overwrite the
            // foreign state. The conflicted lease is abandoned instead.
            dns.restore().unwrap();
            let current = fake
                .current_state("fake:interface:1")
                .unwrap()
                .expect("resource exists");
            assert_eq!(current, foreign_state());
            assert!(!dns.is_active());
        }

        #[test]
        fn crash_between_prepare_and_apply_clears_journal_only() {
            use osdns::testing::{CrashOutcome, FaultInjector, TxPoint, catch_crash};

            let (manager, fake, _dir) = enforce_manager(full_caps());
            let injector = FaultInjector::new();
            injector.crash_at(TxPoint::AfterPrepared);
            manager.install_fault_injector(injector.clone());

            let outcome = catch_crash(|| manager.apply(&global_config()));
            assert!(matches!(outcome, CrashOutcome::Crashed));
            injector.clear();

            // The transaction never became effective: only the journal record
            // is removed, the system is untouched.
            let outcomes = manager.recover_stale().unwrap();
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, RecoveryOutcome::JournalCleared { .. })),
                "expected journal-only cleanup, got {outcomes:?}"
            );
            assert_eq!(
                fake.current_state("fake:global").unwrap(),
                Some(FakeState::Empty)
            );
        }

        #[test]
        fn crash_after_apply_restores_original_state() {
            use osdns::testing::{CrashOutcome, FaultInjector, TxPoint, catch_crash};

            let (manager, fake, _dir) = enforce_manager(full_caps());
            let injector = FaultInjector::new();
            injector.crash_at(TxPoint::AfterApplied);
            manager.install_fault_injector(injector.clone());

            let outcome = catch_crash(|| manager.apply(&global_config()));
            assert!(matches!(outcome, CrashOutcome::Crashed));
            injector.clear();

            // The overlay was effective at crash time...
            assert!(matches!(
                fake.current_state("fake:global").unwrap(),
                Some(FakeState::Configured { .. })
            ));
            // ...so recovery restores the original state.
            let outcomes = manager.recover_stale().unwrap();
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, RecoveryOutcome::Restored { .. })),
                "expected restoration, got {outcomes:?}"
            );
            assert_eq!(
                fake.current_state("fake:global").unwrap(),
                Some(FakeState::Empty)
            );
        }

        #[test]
        fn recovery_reports_external_conflict_and_touches_nothing() {
            use osdns::testing::{CrashOutcome, FaultInjector, TxPoint, catch_crash};

            let (manager, fake, _dir) = enforce_manager(full_caps());
            let injector = FaultInjector::new();
            injector.crash_at(TxPoint::AfterApplied);
            manager.install_fault_injector(injector.clone());
            let outcome = catch_crash(|| manager.apply(&global_config()));
            assert!(matches!(outcome, CrashOutcome::Crashed));
            injector.clear();

            // Another actor changed the resource before recovery ran.
            fake.external_change("fake:global", foreign_state())
                .unwrap();
            let outcomes = manager.recover_stale().unwrap();
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, RecoveryOutcome::ExternalConflict { .. })),
                "expected external conflict, got {outcomes:?}"
            );
            // Ownership is never guessed: the foreign state is left alone.
            assert_eq!(
                fake.current_state("fake:global").unwrap(),
                Some(foreign_state())
            );
        }

        #[test]
        fn locked_resource_reports_busy() {
            use osdns::testing::manager_for_testing_with_policy;

            let dir = tempfile::tempdir().unwrap();
            let fake = FakeDns::with_capabilities(full_caps());
            let crashed = manager_for_testing_with_policy(
                "io.tunnet.test-a",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            // Leave a stale journal record behind via a simulated crash.
            {
                use osdns::testing::{CrashOutcome, FaultInjector, TxPoint, catch_crash};
                let injector = FaultInjector::new();
                injector.crash_at(TxPoint::AfterApplied);
                crashed.install_fault_injector(injector.clone());
                let outcome = catch_crash(|| crashed.apply(&global_config()));
                assert!(matches!(outcome, CrashOutcome::Crashed));
            }
            // Another live lease now owns the resource...
            let holder = manager_for_testing_with_policy(
                "io.tunnet.test-b",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            let _lease = holder.apply(&global_config()).unwrap();
            // ...so recovery skips it instead of fighting the owner.
            let inspector = manager_for_testing_with_policy(
                "io.tunnet.test-c",
                dir.path(),
                &fake,
                Duration::from_secs(5),
                ConflictPolicy::Enforce,
            )
            .unwrap();
            let outcomes = inspector.recover_stale().unwrap();
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, RecoveryOutcome::Busy { .. })),
                "expected busy resource, got {outcomes:?}"
            );
        }

        #[test]
        fn corrupt_journal_fails_closed() {
            let (manager, _fake, dir) = enforce_manager(full_caps());
            let journal_dir = dir.path().join("journal");
            std::fs::create_dir_all(&journal_dir).unwrap();
            std::fs::write(journal_dir.join("bogus.json"), b"{ not valid json").unwrap();
            let err = manager
                .recover_stale()
                .expect_err("corrupt journal must fail closed");
            assert!(matches!(err, osdns::Error::JournalCorrupt(_)));
        }

        const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
        const FOREIGN_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

        fn foreign_state() -> FakeState {
            FakeState::Configured {
                nameservers: vec![FOREIGN_IP],
                search_domains: vec![],
                routing_domains: vec![],
                default_route: None,
            }
        }

        fn global_config() -> DnsConfig {
            DnsConfig::builder(DnsScope::Global)
                .nameserver(IpAddr::V4(RESOLVER_IP))
                .build()
                .unwrap()
        }
    }
}
