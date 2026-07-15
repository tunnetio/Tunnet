use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "tuntun-agent",
    about = "TunTun agent - binds a TUN device and an iroh endpoint"
)]
pub struct Config {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,

    /// Shared bearer token for the control plane.
    #[arg(long, env = "TUNTUN_TOKEN", default_value = "dev-token")]
    pub token: String,

    /// Network name to join.
    #[arg(long, env = "TUNTUN_NETWORK", default_value = "default")]
    pub network: String,

    /// TUN interface name. On macOS this is ignored (kernel picks utunN).
    #[arg(long, env = "TUNTUN_IFNAME", default_value = "tuntun0")]
    pub ifname: String,

    /// Optional hostname override (defaults to the OS hostname).
    #[arg(long, env = "TUNTUN_HOSTNAME")]
    pub hostname: Option<String>,

    /// How often (seconds) to poll the control plane for routing updates.
    #[arg(long, env = "TUNTUN_POLL_SECS", default_value_t = 10)]
    pub poll_secs: u64,

    /// Path to wintun.dll on Windows (default: next to the executable, then "wintun.dll").
    #[cfg(windows)]
    #[arg(long, env = "TUNTUN_WINTUN_FILE")]
    pub wintun_file: Option<String>,
}
