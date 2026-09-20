//! Tunnet agent runtime.
//!
//! This crate is both the `tunnetd` daemon binary and a library, because mobile
//! platforms cannot spawn a daemon process. Android runs the agent in-process
//! inside the app's `VpnService`, so the runtime has to be linkable (see
//! `tunnet-mobile`). The binary is a thin shim over [`run_cli`].

mod accept;
mod actors;
mod cmds_direct;
mod conflict;
mod dataplane;
mod dgram_pump;
mod forward;
mod host_constraints;
mod ingress;
mod metrics;
mod multicast_demand;
mod platform;
mod qos;
pub mod runtime;
mod system_firewall;
#[cfg(feature = "local-api")]
mod system_info;
mod system_routes;
mod tun_io;
mod underlay;
#[cfg(windows)]
mod wintun;

#[cfg(feature = "host-dns")]
mod system_dns;
#[cfg(not(feature = "host-dns"))]
#[path = "system_dns_disabled.rs"]
mod system_dns;

#[cfg(feature = "ssh")]
mod recorder;
#[cfg(feature = "ssh")]
mod ssh;
#[cfg(feature = "ssh")]
mod ssh_nat;

#[cfg(feature = "updater")]
mod auto_update;
#[cfg(feature = "updater")]
mod cmds_update;
#[cfg(feature = "updater")]
mod core_update;

#[cfg(feature = "local-api")]
mod api_bootstrap;
#[cfg(feature = "local-api")]
mod cli;
#[cfg(feature = "local-api")]
mod cmds;
#[cfg(feature = "local-api")]
mod cmds_device;
#[cfg(feature = "local-api")]
mod cmds_login;
#[cfg(all(feature = "local-api", feature = "policy"))]
mod policy_api;

#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(all(feature = "daemon", unix, not(target_os = "android")))]
mod sd_notify;
#[cfg(feature = "daemon")]
mod service;
#[cfg(all(feature = "daemon", unix, not(target_os = "android")))]
mod upgrade;
#[cfg(all(feature = "daemon", windows))]
mod win_service;

pub use host_constraints::{constrain_lan, lan_available, set_lan_available};
pub use multicast_demand::{
    MulticastHost, MulticastLease, clear_multicast_host, multicast_needed, set_multicast_host,
};
#[cfg(any(target_os = "android", all(test, unix)))]
pub use platform::tun as android_tun;
pub use runtime::{
    AgentConfig, AgentError, AgentErrorInfo, AgentErrorKind, AgentHandle, AgentLifecycle,
    AgentMode, AgentNetwork, AgentPeer, AgentRole, AgentRuntime, AgentSnapshot, CreateRequest,
    DataPlaneState, JoinOutcome, JoinRequest, LatestSlot, PeerConnKind, PeerPath, WireNativeResult,
    WireSnapshot, decode_snapshot, encode_snapshot, sanitize_hostname,
};
pub use tunnet_core::{
    PlatformSealer, SealError, SealErrorKind, clear_platform_sealer, set_platform_sealer,
};

/// Install the process-wide rustls provider. Idempotent, and required before
/// any TLS work. Embedders must call this before starting the agent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(feature = "daemon")]
use clap::Parser;

/// `tunnetd` entry point. Parses argv, so only the binary should call it.
#[cfg(feature = "daemon")]
pub fn run_cli() {
    install_crypto_provider();

    #[cfg(feature = "updater")]
    match crate::core_update::maybe_run_activation_worker() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("Core update activation failed: {error:#}");
            exit_with(1);
        }
    }

    #[cfg(windows)]
    if std::env::args().any(|a| a == "--service") {
        if let Err(e) = crate::win_service::run_as_service() {
            eprintln!("{e:#}");
            exit_with(1);
        }
        return;
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to create tokio runtime: {e}");
            exit_with(1);
        }
    };

    if let Err(e) = rt.block_on(async_main()) {
        eprintln!("{e:#}");
        exit_with(1);
    }
}

#[cfg(feature = "daemon")]
fn exit_with(code: i32) -> ! {
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    std::process::exit(code);
}

#[cfg(feature = "daemon")]
async fn async_main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = daemon::DaemonCli::parse();

    daemon::init_logging(&cli);
    daemon::run(cli.state_dir.as_deref(), cli.run).await
}
