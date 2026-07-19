//! Rich CLI subcommands that talk to the running agent over IPC.

use anyhow::Context;
use clap::Args;
use tunnet_core::ipc::IpcClient;
use tunnet_core::ipc::protocol::{
    IpcErrorCode, IpcRequest, IpcResponse, PingProbe, PingSummary, StatusInfo, format_ipc_error,
};
use tunnet_core::{PersistedState, StatePaths};

use crate::output::{self, Output};

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Include peer table
    #[arg(long)]
    pub peers: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct PingArgs {
    /// Peer hostname, mesh IP, or endpoint id
    pub peer: String,
    #[arg(short = 'c', long, default_value_t = 4)]
    pub count: u32,
    #[arg(short = 'i', long, default_value_t = 1.0)]
    pub interval: f64,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct DnsStatusArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to tunnet.toml (defaults to state dir)
    #[arg(long)]
    pub config: Option<String>,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReloadArgs {
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct RouteListArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct RouteAddArgs {
    pub cidr: String,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct DiagArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct NetcheckArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

async fn client(_state_dir: Option<&str>) -> anyhow::Result<IpcClient> {
    Ok(IpcClient::connect())
}

/// Connect to the agent IPC socket, or return a clear "agent not running" error.
pub async fn ipc_or_err(state_dir: Option<&str>) -> anyhow::Result<IpcClient> {
    let ipc = client(state_dir).await?;
    if !tunnet_core::ipc::endpoint_reachable(ipc.path()).await {
        anyhow::bail!("{}", format_ipc_error(&IpcErrorCode::AgentNotRunning, ""));
    }
    Ok(ipc)
}

pub async fn run_status(args: StatusArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let paths = StatePaths::resolve(args.state_dir.as_deref());
    let service = crate::service::probe();

    let Some(persisted) = PersistedState::try_load(&paths)? else {
        let agent_running = service.active;
        if out.json {
            return out.print_json(&serde_json::json!({
                "connected": false,
                "agent_running": agent_running,
                "service": {
                    "installed": service.installed,
                    "active": service.active,
                    "state": service.state,
                },
            }));
        }
        print_system_header(&out, agent_running);
        out.writeln(format!("  network    {}", out.dim("not connected")));
        print_service_lines(&out, &service, agent_running);
        if agent_running {
            out.writeln(out.dim(
                "  Idle - run `sudo tunnet create` / `enroll` / `join` (agent loads automatically).",
            ));
        } else {
            out.writeln(out.dim(
                "  Use `sudo tunnet create` for Direct mode or `tunnet enroll` for Managed mode.",
            ));
        }
        return Ok(());
    };

    let mode = match persisted.mode() {
        tunnet_core::NodeMode::Direct => "Direct",
        tunnet_core::NodeMode::Managed => "Managed",
    };
    let ipc = IpcClient::connect();
    match ipc.request(IpcRequest::Status { peers: args.peers }).await {
        Ok(IpcResponse::Status(info)) => {
            if out.json {
                let mut v = serde_json::to_value(&info)?;
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("mode".into(), serde_json::json!(mode));
                    obj.insert("agent_running".into(), serde_json::json!(true));
                    obj.insert("connected".into(), serde_json::json!(true));
                    obj.insert(
                        "service".into(),
                        serde_json::json!({
                            "installed": service.installed,
                            "active": service.active,
                            "state": service.state,
                        }),
                    );
                }
                return out.print_json(&v);
            }
            print_status(&out, &info, mode, true, &service);
            Ok(())
        }
        Ok(_) => anyhow::bail!("unexpected response from agent"),
        Err(_) => {
            let offline = offline_status(&paths, &persisted);
            if out.json {
                return out.print_json(&serde_json::json!({
                    "connected": true,
                    "agent_running": false,
                    "mode": mode,
                    "hostname": offline.hostname,
                    "ip": offline.ip,
                    "network_name": offline.network_name,
                    "network_id": offline.network_id,
                    "endpoint_id": offline.endpoint_id,
                    "state_dir": paths.dir,
                    "service": {
                        "installed": service.installed,
                        "active": service.active,
                        "state": service.state,
                    },
                }));
            }
            print_offline_status(&out, &offline, mode, &service, &paths.dir);
            Ok(())
        }
    }
}

fn print_system_header(out: &Output, agent_running: bool) {
    if agent_running {
        out.writeln(format!(
            "{}  {}",
            out.online_dot(true),
            out.bold("Agent running")
        ));
    } else {
        out.writeln(format!(
            "{}  {}",
            out.online_dot(false),
            out.bold("Agent not running")
        ));
    }
}

fn print_service_lines(out: &Output, service: &crate::service::ServiceProbe, agent_running: bool) {
    let agent_label = if agent_running {
        out.green("running")
    } else {
        out.yellow("not running")
    };
    out.writeln(format!("  agent      {agent_label}"));
    let service_label = if !service.installed {
        out.dim("not installed")
    } else if service.active {
        out.green(&service.state)
    } else {
        out.yellow(&service.state)
    };
    out.writeln(format!("  service    {service_label}"));
}

struct OfflineStatus {
    hostname: String,
    ip: String,
    network_name: String,
    network_id: String,
    endpoint_id: String,
}

fn offline_status(paths: &StatePaths, persisted: &PersistedState) -> OfflineStatus {
    let policy = tunnet_core::SealPolicy::from_env_and_flag(false);
    let endpoint_id = tunnet_core::load_agent(paths, policy)
        .map(|(id, _, _)| id.endpoint_id_hex())
        .unwrap_or_default();
    match persisted {
        PersistedState::Direct { networks } => {
            let d = networks.first();
            OfflineStatus {
                hostname: d.map(|d| d.hostname.clone()).unwrap_or_else(|| "-".into()),
                ip: d
                    .map(|d| d.assigned_ipv4.to_string())
                    .unwrap_or_else(|| "-".into()),
                network_name: d
                    .map(|d| d.network_name.clone())
                    .unwrap_or_else(|| "-".into()),
                network_id: d
                    .map(|d| d.network_id.to_string())
                    .unwrap_or_else(|| "-".into()),
                endpoint_id,
            }
        }
        PersistedState::Managed(m) => {
            let ip = tunnet_core::state::load_snapshot_cache(paths)
                .and_then(|snap| {
                    snap.memberships
                        .into_iter()
                        .find(|mem| mem.network_id == m.network_id)
                        .map(|mem| mem.assigned_ipv4.to_string())
                })
                .unwrap_or_else(|| "-".into());
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "-".into());
            OfflineStatus {
                hostname,
                ip,
                network_name: m.network_name.clone(),
                network_id: m.network_id.to_string(),
                endpoint_id,
            }
        }
    }
}

fn print_offline_status(
    out: &Output,
    info: &OfflineStatus,
    mode: &str,
    service: &crate::service::ServiceProbe,
    state_dir: &std::path::Path,
) {
    out.writeln(format!(
        "{} {}  {}  {}",
        out.online_dot(false),
        out.bold(&info.hostname),
        out.cyan(&info.ip),
        out.dim(&format!("· {}", info.network_name))
    ));
    out.writeln(format!("  mode       {mode}"));
    if !info.endpoint_id.is_empty() {
        out.writeln(format!(
            "  endpoint   {}",
            out.dim(&output::short_endpoint(&info.endpoint_id))
        ));
    }
    print_service_lines(out, service, false);
    out.writeln(format!(
        "  state      {}",
        out.dim(&state_dir.display().to_string())
    ));
    let system = StatePaths::system_dir();
    if service.installed && state_dir != system.as_path() {
        out.writeln(out.yellow(&format!(
            "  note       service uses {} - CLI state is separate; re-enroll elevated or set TUNNET_STATE_DIR",
            system.display()
        )));
    } else if service.active {
        out.writeln(out.dim("  Service is up but IPC is down - try `tunnet service restart`."));
    } else {
        out.writeln(out.dim("  Start with `tunnet service start` or `tunnet run`."));
    }
}

fn print_status(
    out: &Output,
    info: &StatusInfo,
    mode: &str,
    agent_running: bool,
    service: &crate::service::ServiceProbe,
) {
    let online = out.online_dot(agent_running);
    out.writeln(format!(
        "{} {}  {}  {}",
        online,
        out.bold(&info.hostname),
        out.cyan(&info.ip),
        out.dim(&format!("· {}", info.network_name))
    ));
    out.writeln(format!("  mode       {mode}"));
    if let Some(up) = info.data_plane_up {
        out.writeln(format!(
            "  data plane {}",
            if up { out.green("up") } else { out.dim("down") }
        ));
    }
    if let Some(ka) = info.keep_alive {
        out.writeln(format!(
            "  keep-alive {}",
            if ka { "on" } else { "off (on-demand)" }
        ));
    }
    out.writeln(format!(
        "  endpoint   {}",
        out.dim(&output::short_endpoint(&info.endpoint_id))
    ));
    if let Some(cp) = &info.control {
        let loopback = cp.url.contains("127.0.0.1")
            || cp.url.contains("localhost")
            || cp.url.contains("[::1]");
        let state = if cp.connected {
            out.green("connected")
        } else {
            out.red("disconnected")
        };
        let mut line = format!("  control    {state}  {}", cp.url);
        if let Some(secs) = cp.connected_for_secs {
            line.push_str(&format!("  ·  up {}", output::format_uptime(secs)));
        } else if let Some(secs) = cp.last_change_secs_ago {
            line.push_str(&format!("  ·  {}", output::format_uptime(secs)));
            line.push_str(" ago");
        }
        if cp.reconnects > 0 {
            line.push_str(&format!("  ·  reconnects {}", cp.reconnects));
        }
        out.writeln(line);
        if loopback {
            out.writeln(format!(
                "             {}",
                out.yellow("loopback URL - remote VMs must enroll with the host LAN/public URL")
            ));
        }
        if let Some(err) = &cp.last_error
            && !cp.connected
        {
            out.writeln(format!(
                "             {}",
                out.dim(&format!("last error: {err}"))
            ));
            let skew = err.contains("stale")
                || err.contains("401")
                || err.to_ascii_lowercase().contains("unauthorized");
            if skew {
                out.writeln(format!(
                    "             {}",
                    out.yellow(
                        "hint: sync this machine's clock (VM time drift breaks control auth)"
                    )
                ));
            }
        }
    } else if let Some(url) = &info.control_url {
        let loopback =
            url.contains("127.0.0.1") || url.contains("localhost") || url.contains("[::1]");
        if loopback {
            out.writeln(format!(
                "  control    {} {}",
                out.yellow(url),
                out.yellow("(loopback - remote VMs cannot reach this)")
            ));
        } else {
            out.writeln(format!("  control    {url}"));
        }
    }
    print_service_lines(out, service, agent_running);
    out.writeln(format!(
        "  peers      {} online / {} total",
        info.peers_online, info.peers_total
    ));
    out.writeln(format!("  relay      {}", info.relay_status));
    if let Some(drops) = info.firewall_drops {
        out.writeln(format!(
            "  firewall   {} drops · {} conntrack",
            drops,
            info.conntrack_entries.unwrap_or(0)
        ));
    }
    out.writeln(format!(
        "  uptime     {}  ·  agent v{}  ·  snap {}",
        output::format_uptime(info.uptime_secs),
        info.agent_version,
        info.snapshot_version
    ));
    if let Some(secs) = info.expires_in_secs {
        out.writeln(format!(
            "  expiry     {} remaining",
            output::format_uptime(secs)
        ));
    }

    if let Some(peers) = &info.peers {
        out.writeln("");
        out.writeln(out.bold("Peers"));
        out.writeln(format!(
            "  {:<4} {:<18} {:<14} {:<10} {:<8} {:<10} {}",
            "", "HOSTNAME", "IP", "STATE", "PATH", "RTT", "BYTES"
        ));
        for p in peers {
            let online = out.online_dot(p.online.unwrap_or(false));
            let lat = p
                .latency_ms
                .map(|ms| format!("{ms:.0}ms"))
                .unwrap_or_else(|| out.dim("-"));
            let state = p.conn_state.as_deref().unwrap_or("-");
            let path = p.path.as_deref().unwrap_or("-");
            let bytes = match (p.bytes_in, p.bytes_out) {
                (Some(i), Some(o)) => format!("↓{} ↑{}", fmt_bytes(i), fmt_bytes(o)),
                _ => out.dim("-"),
            };
            out.writeln(format!(
                "  {online:<4} {:<18} {:<14} {:<10} {:<8} {lat:<10} {bytes}",
                truncate(&p.hostname, 18),
                p.ip,
                truncate(state, 10),
                truncate(path, 8),
            ));
        }
    }
}

pub async fn run_ping(args: PingArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let interval_ms = (args.interval * 1000.0).max(50.0) as u64;

    if !out.json {
        out.writeln(format!("PING {} via Tunnet mesh", out.bold(&args.peer)));
    }

    let mut probes: Vec<PingProbe> = Vec::new();
    let mut summary: Option<PingSummary> = None;

    ipc.request_stream(
        IpcRequest::Ping {
            peer: args.peer.clone(),
            count: args.count,
            interval_ms,
        },
        |resp| {
            match resp {
                IpcResponse::PingProbe(p) => {
                    if out.json {
                        probes.push(p);
                    } else {
                        out.writeln(format!(
                            "{} bytes from {} ({}): seq={} time={:.2} ms path={}",
                            8, p.peer, p.peer_ip, p.seq, p.latency_ms, p.path
                        ));
                    }
                }
                IpcResponse::PingSummary(s) => {
                    summary = Some(s);
                }
                IpcResponse::Error { code, message } if !out.json => {
                    out.writeln(out.red(&format!("  {}", format_ipc_error(&code, &message))));
                }
                _ => {}
            }
            Ok(())
        },
    )
    .await?;

    if out.json {
        let payload = serde_json::json!({
            "probes": probes,
            "summary": summary,
        });
        return out.print_json(&payload);
    }

    if let Some(s) = summary {
        out.writeln("");
        out.writeln(format!("--- {} ping statistics ---", s.peer));
        out.writeln(format!(
            "{} transmitted, {} received, {:.1}% packet loss",
            s.transmitted, s.received, s.loss_pct
        ));
        if let (Some(min), Some(avg), Some(max)) = (s.min_ms, s.avg_ms, s.max_ms) {
            out.writeln(format!(
                "rtt min/avg/max = {:.2}/{:.2}/{:.2} ms  path={}",
                min, avg, max, s.path
            ));
        }
    }
    Ok(())
}

pub async fn run_dns_status(args: DnsStatusArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc.request(IpcRequest::DnsStatus).await?;
    let IpcResponse::DnsStatus(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    let active = if info.peer_dns_active {
        out.green("active")
    } else {
        out.red("inactive")
    };
    out.writeln(format!("PeerDNS   {active}"));
    out.writeln(format!("suffix    .{}", info.suffix));
    out.writeln(format!(
        "upstream  {}",
        if info.upstream.is_empty() {
            out.dim("none")
        } else {
            info.upstream.join(", ")
        }
    ));
    out.writeln(format!("cache     {} entries", info.cached_entries));
    out.writeln(format!("synthetic {}", info.synthetic_base));
    out.writeln(format!("magic     {}", info.magic_ip));
    out.writeln(format!("bind      {}", info.bind));
    Ok(())
}

pub async fn run_validate(args: ValidateArgs) -> anyhow::Result<()> {
    use tunnet_core::TunnetConfig;

    let paths = StatePaths::resolve(args.state_dir.as_deref());
    let cfg = if let Some(path) = &args.config {
        TunnetConfig::load_path(std::path::Path::new(path))?
    } else {
        TunnetConfig::ensure(&paths)?
    };
    match cfg.validate() {
        Ok(()) => {
            println!("tunnet.toml: ok");
            Ok(())
        }
        Err(errs) => {
            for e in &errs {
                eprintln!("error: {e}");
            }
            anyhow::bail!("{} validation error(s)", errs.len());
        }
    }
}

pub async fn run_reload(args: ReloadArgs) -> anyhow::Result<()> {
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc.request(IpcRequest::Reload).await?;
    match resp {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_route_list(args: RouteListArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc.request(IpcRequest::RouteList).await?;
    let IpcResponse::Routes(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }

    out.writeln(out.bold("Subnet routes"));
    if info.subnet_routes.is_empty() {
        out.writeln(out.dim("  (none)"));
    } else {
        for r in &info.subnet_routes {
            let self_tag = if r.advertised_by_self {
                out.yellow(" [self]")
            } else {
                String::new()
            };
            out.writeln(format!(
                "  {} via {} ({}){self_tag}",
                out.cyan(&r.cidr),
                r.via_hostname,
                r.via_ip
            ));
        }
    }

    out.writeln("");
    out.writeln(out.bold("Hostname routes"));
    if info.hostname_routes.is_empty() {
        out.writeln(out.dim("  (none)"));
    } else {
        for r in &info.hostname_routes {
            let name = if r.is_wildcard {
                format!("*.{}", r.hostname)
            } else {
                r.hostname.clone()
            };
            out.writeln(format!(
                "  {} via {} ({})",
                out.cyan(&name),
                r.via_hostname,
                r.via_ip
            ));
        }
    }

    out.writeln("");
    out.writeln(out.bold("Exit node"));
    match &info.exit_node {
        Some(e) => out.writeln(format!(
            "  {} ({}) {}",
            e.hostname,
            e.via_ip,
            out.dim(&output::short_endpoint(&e.endpoint_id))
        )),
        None => out.writeln(out.dim("  (none)")),
    }

    out.writeln("");
    out.writeln(format!(
        "Split tunnel: {} {}",
        info.split_tunnel_mode,
        if info.split_tunnel_cidrs.is_empty() {
            String::new()
        } else {
            format!("[{}]", info.split_tunnel_cidrs.join(", "))
        }
    ));
    Ok(())
}

pub async fn run_route_add(args: RouteAddArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc
        .request(IpcRequest::RouteAdd {
            cidr: args.cidr,
            description: args.description,
        })
        .await?;
    match resp {
        IpcResponse::RouteAdded { cidr } => {
            if out.json {
                out.print_json(&serde_json::json!({ "cidr": cidr, "status": "accepted" }))?;
            } else {
                out.writeln(format!(
                    "{} Route {} advertised to control plane",
                    out.green("✓"),
                    out.cyan(&cidr)
                ));
            }
            Ok(())
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_diag(args: DiagArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc.request(IpcRequest::Diag).await?;
    let IpcResponse::Diag(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(out.bold("Diagnostics"));
    out.writeln(format!("  NAT type          {}", info.nat_type));
    out.writeln(format!(
        "  Endpoint          {} ({})",
        output::short_endpoint(&info.endpoint_id),
        if info.endpoint_online {
            out.green("online")
        } else {
            out.red("offline")
        }
    ));
    out.writeln(format!(
        "  Relay             {}{}",
        if info.relay_reachable {
            out.green("reachable")
        } else {
            out.red("unreachable")
        },
        info.relay_rtt_ms
            .map(|ms| format!(" ({ms:.1} ms)"))
            .unwrap_or_default()
    ));
    out.writeln(format!(
        "  Peers             {} total · {} direct · {} relayed",
        info.total_peers, info.direct_peers, info.relayed_peers
    ));
    if !info.notes.is_empty() {
        out.writeln("");
        for n in &info.notes {
            out.writeln(format!("  {}", out.dim(&format!("· {n}"))));
        }
    }
    Ok(())
}

pub async fn run_netcheck(args: NetcheckArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let ipc = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = ipc.request(IpcRequest::Netcheck).await?;
    let IpcResponse::Netcheck(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    for c in &info.checks {
        let mark = if c.pass {
            out.green("PASS")
        } else {
            out.red("FAIL")
        };
        out.writeln(format!("  [{mark}] {:<16} {}", c.name, out.dim(&c.detail)));
    }
    out.writeln("");
    if info.ok {
        out.writeln(format!("{} netcheck passed", out.green("✓")));
    } else {
        out.writeln(format!("{} netcheck failed", out.red("✗")));
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub command: Option<ServeSubcommand>,
    /// Local port to expose (when starting without a subcommand)
    pub port: Option<u16>,
    #[arg(long, default_value = "tcp")]
    pub protocol: String,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum ServeSubcommand {
    /// List active serves
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// Stop serving a port
    Off {
        port: u16,
        #[arg(long)]
        json: bool,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
}

pub async fn run_serve(args: ServeArgs) -> anyhow::Result<()> {
    match args.command {
        Some(ServeSubcommand::Status { json, state_dir }) => {
            run_serve_status(json, state_dir.as_deref()).await
        }
        Some(ServeSubcommand::Off {
            port,
            json,
            state_dir,
        }) => run_serve_off(port, json, state_dir.as_deref()).await,
        None => {
            let port = args.port.context(
                "usage: tunnet serve <port> | tunnet serve status | tunnet serve off <port>",
            )?;
            run_serve_start(port, &args.protocol, args.json, args.state_dir.as_deref()).await
        }
    }
}

async fn run_serve_start(
    port: u16,
    protocol: &str,
    json: bool,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc
        .request(IpcRequest::ServeStart {
            port,
            protocol: protocol.to_string(),
            certificate_pem: None,
            private_key_pem: None,
            internal_hostname: None,
            serve_id: None,
        })
        .await?;
    let IpcResponse::Serve(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!(
        "{} Serve active at {}",
        out.green("✓"),
        out.cyan(&info.url)
    ));
    Ok(())
}

async fn run_serve_status(json: bool, state_dir: Option<&str>) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc.request(IpcRequest::ServeStatus).await?;
    let IpcResponse::Serves { serves } = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&serves);
    }
    if serves.is_empty() {
        out.writeln(out.dim("No active serves."));
        return Ok(());
    }
    for s in serves {
        out.writeln(format!(
            "{}  {}  {}  {}",
            out.online_dot(s.status == "active"),
            out.cyan(&s.url),
            s.protocol,
            out.dim(&s.status)
        ));
    }
    Ok(())
}

async fn run_serve_off(port: u16, json: bool, state_dir: Option<&str>) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc.request(IpcRequest::ServeOff { port }).await?;
    let IpcResponse::Serve(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!("{} Stopped serve on port {port}", out.green("✓")));
    let _ = info;
    Ok(())
}

// ---------- tunnel ----------

#[derive(clap::Args, Debug)]
pub struct TunnelArgs {
    #[command(subcommand)]
    pub command: Option<TunnelSubcommand>,
    /// Local port to expose publicly (when starting without a subcommand)
    pub port: Option<u16>,
    #[arg(long, default_value = "https")]
    pub protocol: String,
    /// Relay id, name, or omit for auto
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub subdomain: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum TunnelSubcommand {
    /// List active tunnels
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// Stop a public tunnel
    Off {
        port: u16,
        #[arg(long)]
        json: bool,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
}

pub async fn run_tunnel(args: TunnelArgs) -> anyhow::Result<()> {
    match args.command {
        Some(TunnelSubcommand::Status { json, state_dir }) => {
            run_tunnel_status(json, state_dir.as_deref()).await
        }
        Some(TunnelSubcommand::Off {
            port,
            json,
            state_dir,
        }) => run_tunnel_off(port, json, state_dir.as_deref()).await,
        None => {
            let port = args.port.context(
                "usage: tunnet tunnel <port> | tunnet tunnel status | tunnet tunnel off <port>",
            )?;
            run_tunnel_start(
                port,
                &args.protocol,
                args.relay.as_deref(),
                args.subdomain.as_deref(),
                args.json,
                args.state_dir.as_deref(),
            )
            .await
        }
    }
}

async fn run_tunnel_start(
    port: u16,
    protocol: &str,
    relay: Option<&str>,
    subdomain: Option<&str>,
    json: bool,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc
        .request(IpcRequest::TunnelStart {
            port,
            protocol: protocol.to_string(),
            relay: relay.map(str::to_string),
            subdomain: subdomain.map(str::to_string),
        })
        .await?;
    let IpcResponse::Tunnel(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!(
        "{} Tunnel active at {}",
        out.green("✓"),
        out.cyan(&info.public_url)
    ));
    Ok(())
}

async fn run_tunnel_status(json: bool, state_dir: Option<&str>) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc.request(IpcRequest::TunnelStatus).await?;
    let IpcResponse::Tunnels { tunnels } = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&tunnels);
    }
    if tunnels.is_empty() {
        out.writeln(out.dim("No active tunnels."));
        return Ok(());
    }
    for t in tunnels {
        out.writeln(format!(
            "{}  {}  :{}  {}  {}",
            out.online_dot(t.status == "active"),
            out.cyan(&t.public_url),
            t.port,
            t.protocol,
            out.dim(&t.status)
        ));
    }
    Ok(())
}

async fn run_tunnel_off(port: u16, json: bool, state_dir: Option<&str>) -> anyhow::Result<()> {
    let out = Output::new(json);
    let ipc = ipc_or_err(state_dir).await?;
    let resp = ipc.request(IpcRequest::TunnelOff { port }).await?;
    let IpcResponse::Tunnel(info) = resp else {
        anyhow::bail!("unexpected response");
    };
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!("{} Stopped tunnel on port {port}", out.green("✓")));
    let _ = info;
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

fn fmt_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.1}G", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1}M", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1}K", n as f64 / KB as f64)
    } else {
        format!("{n}B")
    }
}

/// Shared helper kept for future serve/tunnel CLI modules.
#[allow(dead_code)]
pub async fn ensure_agent(state_dir: Option<&str>) -> anyhow::Result<IpcClient> {
    ipc_or_err(state_dir).await
}

pub async fn run_up(state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = ipc_or_err(state_dir).await?;
    match ipc.request(IpcRequest::DataPlaneUp).await? {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn run_down(state_dir: Option<&str>) -> anyhow::Result<()> {
    let ipc = ipc_or_err(state_dir).await?;
    match ipc.request(IpcRequest::DataPlaneDown).await? {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message))
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub async fn wait_until_agent(state_dir: Option<&str>, secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last_err = None;
    while tokio::time::Instant::now() < deadline {
        match ipc_or_err(state_dir).await {
            Ok(_) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("agent did not become ready within {secs}s")))
        .with_context(|| {
            format!(
                "agent not ready after {secs}s; check `tunnet service status` / `tunnet status`"
            )
        })
}
