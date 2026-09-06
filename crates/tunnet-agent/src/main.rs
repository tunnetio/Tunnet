mod accept;
mod actors;
mod api_bootstrap;
mod auto_update;
mod cidr_collision;
mod cli;
mod cmds;
mod cmds_device;
mod cmds_direct;
mod cmds_login;
mod cmds_update;
mod core_update;
mod daemon;
mod dataplane;
mod dgram_pump;
mod forward;
mod ingress;
mod magic_dns;
mod metrics;
mod policy_api;
mod qos;
mod recorder;
mod runtime;
#[cfg(unix)]
mod sd_notify;
mod service;
mod ssh;
mod ssh_nat;
mod system_dns;
mod system_firewall;
mod system_info;
mod system_routes;
mod tun_io;
mod underlay;
#[cfg(unix)]
mod upgrade;
#[cfg(windows)]
mod win_service;
#[cfg(windows)]
mod wintun;

use clap::Parser;

fn main() {
    ensure_rustls_crypto_provider();

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

fn ensure_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");
}

fn exit_with(code: i32) -> ! {
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    std::process::exit(code);
}

async fn async_main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = daemon::DaemonCli::parse();

    daemon::init_logging(&cli);
    daemon::run(cli.state_dir.as_deref(), cli.run).await
}
