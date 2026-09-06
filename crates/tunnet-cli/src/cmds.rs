//! Rich CLI subcommands that talk to the running agent over IPC.

use crate::state::{PersistedState, StatePaths};
use anyhow::Context;
use clap::Args;
use tunnet_client::{
    ApiErrorCode, NetworkSummary, NodeSummary, PeerSummary, PingEvent, PingProbe, PingSummary,
    TunnetClient, format_api_error,
};
use tunnet_common::local_api::{ServeStartRequest, TunnelStartRequest};

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

async fn client(_state_dir: Option<&str>) -> anyhow::Result<TunnetClient> {
    Ok(TunnetClient::connect())
}

/// Connect to the Local API, or return a clear "daemon not running" error.
pub async fn ipc_or_err(state_dir: Option<&str>) -> anyhow::Result<TunnetClient> {
    let client = client(state_dir).await?;
    if !tunnet_client::endpoint_reachable(client.path()).await {
        anyhow::bail!("{}", format_api_error(&ApiErrorCode::DaemonNotRunning, ""));
    }
    Ok(client)
}

pub async fn wait_until_daemon(state_dir: Option<&str>, secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last_err = None;
    while tokio::time::Instant::now() < deadline {
        match ipc_or_err(state_dir).await {
            Ok(_) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("daemon did not become ready within {secs}s")))
        .context("daemon not ready; check `tunnet service status` / `tunnet status`")
}

/// True when the Local API dropped the connection mid-request (common when the
/// daemon reloads after create/join/enroll).
pub fn is_api_connection_closed(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("connection closed")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("unexpected eof")
}

/// After a mid-reload disconnect, wait for the daemon and treat success if state exists.
pub async fn recover_bootstrap_result(
    state_dir: Option<&str>,
    verb: &str,
    original: anyhow::Error,
) -> anyhow::Result<()> {
    if let Err(e) = wait_until_daemon(state_dir, 30).await {
        return Err(original.context(format!(
            "Local API closed during {verb}; daemon did not come back: {e:#}"
        )));
    }
    let paths = StatePaths::resolve(state_dir);
    match PersistedState::try_load(&paths)? {
        Some(_) => {
            println!("Network {verb} (daemon reloaded).");
            Ok(())
        }
        None => Err(original.context(format!(
            "Local API closed during {verb}, and no network state was found afterward"
        ))),
    }
}

fn read_yes_no() -> anyhow::Result<bool> {
    use std::io::{Write, stdin, stdout};
    stdout().flush()?;
    let mut line = String::new();
    stdin().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}

/// Ensure `tunnetd` is reachable. If not, prompt to start the service (and
/// elevate on Windows). Used by create / join / enroll.
pub async fn ensure_daemon_running(
    state_dir: Option<&str>,
    purpose: &str,
) -> anyhow::Result<TunnetClient> {
    let client = client(state_dir).await?;
    if tunnet_client::endpoint_reachable(client.path()).await {
        return Ok(client);
    }

    if !tunnet_service::is_admin() {
        println!("tunnetd must be running to {purpose}.");
        eprint!("Start the daemon now? [y/N] ");
        if !read_yes_no()? {
            anyhow::bail!(
                "daemon must be running to {purpose}.\n\
                 Start it with `tunnet service start` (or run `tunnetd` in the foreground)."
            );
        }
        // Elevate; the elevated process re-runs this command and starts the daemon.
        tunnet_service::ensure_admin()?;
    }

    if !tunnet_client::endpoint_reachable(client.path()).await {
        tunnet_service::start(state_dir)?;
        wait_until_daemon(state_dir, 60).await?;
    }
    ipc_or_err(state_dir).await
}

pub async fn run_status(args: StatusArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let paths = StatePaths::resolve(args.state_dir.as_deref());
    let service = tunnet_service::probe();
    let client = TunnetClient::connect();
    let daemon_up = tunnet_client::endpoint_reachable(client.path()).await;

    let Some(persisted) = PersistedState::try_load(&paths)? else {
        if out.json {
            return out.print_json(&serde_json::json!({
                "connected": false,
                "daemon_running": daemon_up,
                "service": {
                    "installed": service.installed,
                    "active": service.active,
                    "state": service.state,
                },
            }));
        }
        print_system_header(&out, daemon_up);
        out.writeln(format!("  network    {}", out.dim("not connected")));
        print_daemon_lines(&out, daemon_up, &service);
        if daemon_up {
            out.writeln(out.dim(
                "  Idle - run `tunnet create` / `enroll` / `join` (daemon reloads automatically).",
            ));
        } else {
            out.writeln(out.dim(
                "  Start the daemon with `tunnet service start` (or `tunnetd` for foreground).",
            ));
        }
        return Ok(());
    };

    let mode = persisted.mode();
    if daemon_up {
        match client.node().await {
            Ok(node) => {
                let peers_by_network = if args.peers {
                    fetch_peers_by_network(&client, &node).await?
                } else {
                    std::collections::HashMap::new()
                };
                if out.json {
                    let mut v = serde_json::to_value(&node)?;
                    if args.peers
                        && let Some(obj) = v.as_object_mut()
                        && let Some(networks) =
                            obj.get_mut("networks").and_then(|n| n.as_array_mut())
                    {
                        for net in networks {
                            if let Some(id) = net.get("network_id").and_then(|id| id.as_str())
                                && let Some(peers) = peers_by_network.get(id)
                                && let Some(net_obj) = net.as_object_mut()
                            {
                                net_obj.insert("peers".into(), serde_json::to_value(peers)?);
                            }
                        }
                    }
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("mode".into(), serde_json::json!(mode));
                        obj.insert("daemon_running".into(), serde_json::json!(true));
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
                print_status(&out, &node, &peers_by_network, mode, true, &service);
                return Ok(());
            }
            Err(e) => {
                let msg = e.to_string();
                if out.json {
                    return out.print_json(&serde_json::json!({
                        "connected": true,
                        "daemon_running": false,
                        "api_reachable": true,
                        "api_error": msg,
                        "mode": mode,
                        "service": {
                            "installed": service.installed,
                            "active": service.active,
                            "state": service.state,
                        },
                    }));
                }
                let offline = offline_status(&paths, &persisted);
                out.writeln(format!(
                    "{} {}  {}  {}",
                    out.online_dot(false),
                    out.bold(&offline.hostname),
                    out.cyan(&offline.ip),
                    out.dim(&format!("· {}", offline.network_name))
                ));
                out.writeln(format!("  mode       {mode}"));
                print_daemon_lines(&out, false, &service);
                out.writeln(format!(
                    "  state      {}",
                    out.dim(&paths.dir.display().to_string())
                ));
                out.writeln(out.dim(&format!("  Local API error: {msg}")));
                out.writeln(out.dim("  Fix: `tunnet service restart`"));
                return Ok(());
            }
        }
    }

    let offline = offline_status(&paths, &persisted);
    if out.json {
        return out.print_json(&serde_json::json!({
            "connected": true,
            "daemon_running": false,
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

fn print_system_header(out: &Output, daemon_up: bool) {
    if daemon_up {
        out.writeln(format!(
            "{}  {}",
            out.online_dot(true),
            out.bold("Daemon running")
        ));
    } else {
        out.writeln(format!(
            "{}  {}",
            out.online_dot(false),
            out.bold("Daemon not running")
        ));
    }
}

/// One truth: Local API up = daemon up. Service is only how the OS keeps `tunnetd` alive.
fn print_daemon_lines(out: &Output, daemon_up: bool, service: &tunnet_service::ServiceProbe) {
    let daemon_label = if daemon_up {
        out.green("running")
    } else {
        out.yellow("stopped")
    };
    out.writeln(format!("  daemon     {daemon_label}"));

    let autostart = if !service.installed {
        out.dim("not installed")
    } else if service.active && daemon_up {
        out.green("service (running)")
    } else if service.active && !daemon_up {
        out.yellow("service (not responding)")
    } else if service.installed {
        out.yellow(&format!("service ({})", service.state))
    } else {
        out.dim("not installed")
    };
    out.writeln(format!("  autostart  {autostart}"));
}

fn print_service_lines(out: &Output, service: &tunnet_service::ServiceProbe, agent_running: bool) {
    print_daemon_lines(out, agent_running, service);
}

struct OfflineStatus {
    hostname: String,
    ip: String,
    network_name: String,
    network_id: String,
    endpoint_id: String,
}

fn offline_status(_paths: &StatePaths, persisted: &PersistedState) -> OfflineStatus {
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
                endpoint_id: String::new(),
            }
        }
        PersistedState::Managed(m) => {
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "-".into());
            OfflineStatus {
                hostname,
                ip: "-".into(),
                network_name: m.network_name.clone(),
                network_id: m.network_id.to_string(),
                endpoint_id: String::new(),
            }
        }
    }
}

fn print_offline_status(
    out: &Output,
    info: &OfflineStatus,
    mode: &str,
    service: &tunnet_service::ServiceProbe,
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
    print_daemon_lines(out, false, service);
    out.writeln(format!(
        "  state      {}",
        out.dim(&state_dir.display().to_string())
    ));
    if service.active {
        out.writeln(
            out.dim("  Service is up but Local API is down. Fix: `tunnet service restart`"),
        );
    } else {
        out.writeln(out.dim("  Start with `tunnet service start`."));
    }
}

fn print_status(
    out: &Output,
    node: &NodeSummary,
    peers_by_network: &std::collections::HashMap<String, Vec<PeerSummary>>,
    mode: &str,
    agent_running: bool,
    service: &tunnet_service::ServiceProbe,
) {
    let online = out.online_dot(agent_running);
    let primary = node.networks.first();
    let primary_ip = primary.map(|n| n.ip.as_str()).unwrap_or("-");
    let primary_name = primary
        .map(|n| n.network_name.as_str())
        .unwrap_or("no network");
    out.writeln(format!(
        "{} {}  {}  {}",
        online,
        out.bold(&node.hostname),
        out.cyan(primary_ip),
        out.dim(&format!("· {primary_name}"))
    ));
    out.writeln(format!("  mode       {mode}"));
    // Dataplane health: never a bare "up" when the packet worker is dead.
    // Prefer the detailed state; fall back to the legacy boolean for old
    // daemons that do not report it yet.
    let dp_line = match node.data_plane.as_ref() {
        Some(dp) => match dp.state.as_str() {
            "up" => format!("  data plane {}", out.green("up")),
            "degraded" => format!(
                "  data plane {} (outbound worker dead, restarts: {}){}",
                out.yellow("degraded"),
                dp.restart_count,
                dp.last_error
                    .as_ref()
                    .map(|e| format!(" · {}", out.dim(e)))
                    .unwrap_or_default()
            ),
            "restarting" => format!(
                "  data plane {} (restarts: {}){}",
                out.yellow("restarting"),
                dp.restart_count,
                dp.last_error
                    .as_ref()
                    .map(|e| format!(" · {}", out.dim(e)))
                    .unwrap_or_default()
            ),
            other => format!("  data plane {}", out.dim(other)),
        },
        None => format!(
            "  data plane {}",
            if node.data_plane_up {
                out.green("up")
            } else {
                out.dim("down")
            }
        ),
    };
    out.writeln(dp_line);
    out.writeln(format!(
        "  endpoint   {}",
        out.dim(&output::short_endpoint(&node.endpoint_id))
    ));

    if let Some(cp) = &node.control {
        print_control_plane(out, cp);
    }

    print_service_lines(out, service, agent_running);
    let mut uptime = String::new();
    jiff::fmt::friendly::SpanPrinter::new()
        .print_unsigned_duration(
            &std::time::Duration::from_secs(node.uptime_secs),
            &mut uptime,
        )
        .expect("formatting a duration into a String cannot fail");
    out.writeln(format!(
        "  uptime     {}  ·  daemon v{}  ·  snap {}",
        uptime, node.daemon_version, node.snapshot_version
    ));
    // Build identity: a bare version (v0.9.1) cannot distinguish
    // protocol-breaking pre-1.0 commits. Show both sides' git hashes and
    // warn loudly on mismatch (the classic stale-daemon trap: fresh CLI
    // talking to an old service binary).
    let cli_git = tunnet_common::git_hash();
    let mut build_line = format!("  build      cli {cli_git}");
    if let Some(dg) = node.daemon_git.as_deref() {
        build_line.push_str(&format!("  ·  daemon {dg}"));
        if dg != "unknown" && cli_git != "unknown" && dg != cli_git {
            build_line.push_str(&format!(
                "  ·  {}",
                out.red("MISMATCH: daemon and CLI built from different commits — restart/redeploy the daemon")
            ));
        }
    }
    if let Some(alpn) = node.tunnel_alpn.as_deref() {
        build_line.push_str(&format!("  ·  {alpn}"));
    }
    out.writeln(build_line);

    if let Some(od) = &node.on_demand {
        out.writeln(format!(
            "  on-demand  {} ok / {} fail · {} buffered",
            od.reconnect_success, od.reconnect_fail, od.packets_buffered
        ));
    }

    for net in &node.networks {
        out.writeln("");
        print_network_section(out, net, peers_by_network.get(&net.network_id));
    }
}

fn print_control_plane(out: &Output, cp: &tunnet_common::local_api::ControlPlaneStatusInfo) {
    let loopback =
        cp.url.contains("127.0.0.1") || cp.url.contains("localhost") || cp.url.contains("[::1]");
    let state = if cp.connected {
        out.green("connected")
    } else {
        out.red("disconnected")
    };
    let mut line = format!("  control    {state}  {}", cp.url);
    if let Some(secs) = cp.connected_for_secs {
        let mut duration = String::new();
        jiff::fmt::friendly::SpanPrinter::new()
            .print_unsigned_duration(&std::time::Duration::from_secs(secs), &mut duration)
            .expect("formatting a duration into a String cannot fail");
        line.push_str(&format!("  ·  up {duration}"));
    } else if let Some(secs) = cp.last_change_secs_ago {
        let mut duration = String::new();
        jiff::fmt::friendly::SpanPrinter::new()
            .print_unsigned_duration(&std::time::Duration::from_secs(secs), &mut duration)
            .expect("formatting a duration into a String cannot fail");
        line.push_str(&format!("  ·  {duration}"));
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
                out.yellow("hint: sync this machine's clock (VM time drift breaks control auth)")
            ));
        }
    }
}

fn print_network_section(out: &Output, net: &NetworkSummary, peers: Option<&Vec<PeerSummary>>) {
    out.writeln(out.bold(&format!("Network: {}", net.network_name)));
    out.writeln(format!("  ip         {}", out.cyan(&net.ip)));
    out.writeln(format!("  role       {}  ·  {}", net.role, net.mode));
    if let Some(ka) = net.keep_alive {
        out.writeln(format!(
            "  keep-alive {}",
            if ka { "on" } else { "off (on-demand)" }
        ));
    }
    if let Some(cp) = &net.control {
        print_control_plane(out, cp);
    } else if let Some(url) = &net.control_url {
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
    out.writeln(format!(
        "  peers      {} online / {} total",
        net.peers_online, net.peers_total
    ));
    out.writeln(format!("  relay      {}", net.relay_status));
    if let Some(drops) = net.firewall_drops {
        out.writeln(format!(
            "  firewall   {} drops · {} conntrack",
            drops,
            net.conntrack_entries.unwrap_or(0)
        ));
    }
    if let Some(secs) = net.expires_in_secs {
        let mut duration = String::new();
        jiff::fmt::friendly::SpanPrinter::new()
            .print_unsigned_duration(&std::time::Duration::from_secs(secs), &mut duration)
            .expect("formatting a duration into a String cannot fail");
        out.writeln(format!("  expiry     {} remaining", duration));
    }

    if let Some(peers) = peers {
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

async fn fetch_peers_by_network(
    client: &TunnetClient,
    node: &NodeSummary,
) -> anyhow::Result<std::collections::HashMap<String, Vec<PeerSummary>>> {
    let mut out = std::collections::HashMap::new();
    for net in &node.networks {
        let resp = client.network_peers(&net.network_id).await?;
        out.insert(net.network_id.clone(), resp.peers);
    }
    Ok(out)
}

pub async fn run_ping(args: PingArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let interval_ms = (args.interval * 1000.0).max(50.0) as u64;

    if !out.json {
        out.writeln(format!("PING {} via Tunnet mesh", out.bold(&args.peer)));
    }

    let mut probes: Vec<PingProbe> = Vec::new();
    let mut summary: Option<PingSummary> = None;

    match client
        .ping(&args.peer, args.count, interval_ms, |event| {
            match event {
                PingEvent::Probe(p) => {
                    if out.json {
                        probes.push(p);
                    } else {
                        out.writeln(format!(
                            "{} bytes from {} ({}): seq={} time={:.2} ms path={}",
                            8, p.peer, p.peer_ip, p.seq, p.latency_ms, p.path
                        ));
                    }
                }
                PingEvent::Summary(s) => {
                    summary = Some(s);
                }
            }
            Ok(())
        })
        .await
    {
        Err(e) if !out.json => {
            out.writeln(out.red(&format!("  {e}")));
        }
        Err(e) => return Err(e),
        Ok(()) => {}
    }

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
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let info = client.dns().await?;
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
    out.writeln(format!(
        "dnssec    {}",
        if info.dnssec {
            out.green("validate")
        } else {
            out.dim("off")
        }
    ));
    out.writeln(format!("cache     {} entries", info.cached_entries));
    out.writeln(format!("synthetic {}", info.synthetic_base));
    out.writeln(format!("magic     {}", info.magic_ip));
    out.writeln(format!("bind      {}", info.bind));
    Ok(())
}

pub async fn run_validate(args: ValidateArgs) -> anyhow::Result<()> {
    use tunnet_common::local_api::ValidateConfigRequest;

    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let body = ValidateConfigRequest {
        path: args.config,
        contents: None,
    };
    let resp = client.validate_config(&body).await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_reload(args: ReloadArgs) -> anyhow::Result<()> {
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = client.reload().await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_route_list(args: RouteListArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let info = client.routes_list(None).await?;
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
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let resp = client.routes_add(args.cidr, args.description).await?;
    if out.json {
        out.print_json(&serde_json::json!({ "cidr": resp.cidr, "status": "accepted" }))?;
    } else {
        out.writeln(format!(
            "{} Route {} advertised to control plane",
            out.green("✓"),
            out.cyan(&resp.cidr)
        ));
    }
    Ok(())
}

pub async fn run_diag(args: DiagArgs) -> anyhow::Result<()> {
    let out = Output::new(args.json);
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let info = client.diag().await?;
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
    let client = ipc_or_err(args.state_dir.as_deref()).await?;
    let info = client.netcheck().await?;
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
    /// Allow peers with this tag (`tag:frontend` or `frontend`). Repeatable.
    #[arg(long = "allow", value_name = "SELECTOR")]
    pub allow: Vec<String>,
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
    /// Stop and remove a serve
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
            run_serve_start(
                port,
                &args.protocol,
                &args.allow,
                args.json,
                args.state_dir.as_deref(),
            )
            .await
        }
    }
}

async fn run_serve_start(
    port: u16,
    protocol: &str,
    allow: &[String],
    json: bool,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let out = Output::new(json);
    let mut allowed_tags = Vec::new();
    let mut allowed_endpoint_ids = Vec::new();
    for raw in allow {
        let s = raw.trim();
        if let Some(tag) = s.strip_prefix("tag:") {
            allowed_tags.push(tag.to_string());
        } else if s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            allowed_endpoint_ids.push(s.to_lowercase());
        } else {
            allowed_tags.push(s.to_string());
        }
    }
    let access_mode = if !allowed_endpoint_ids.is_empty() {
        Some("machines".to_string())
    } else if !allowed_tags.is_empty() {
        Some("tags".to_string())
    } else {
        None
    };
    let client = ipc_or_err(state_dir).await?;
    let body = ServeStartRequest {
        port,
        protocol: protocol.to_string(),
        certificate_pem: None,
        private_key_pem: None,
        internal_hostname: None,
        serve_id: None,
        access_mode,
        allowed_tags,
        allowed_endpoint_ids,
    };
    let info = client.serves_start(&body).await?;
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
    let client = ipc_or_err(state_dir).await?;
    let resp = client.serves_list().await?;
    let serves = resp.serves;
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
    let client = ipc_or_err(state_dir).await?;
    let info = client.serves_off(port).await?;
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!("{} Removed serve on port {port}", out.green("✓")));
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
    /// Edge id, name, or omit for auto
    #[arg(long)]
    pub edge: Option<String>,
    #[arg(long)]
    pub subdomain: Option<String>,
    /// Capture HTTP traffic and open a local inspector UI
    #[arg(long)]
    pub inspect: bool,
    /// Inspector bind address (default `127.0.0.1:4040`)
    #[arg(long)]
    pub inspect_addr: Option<String>,
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
                args.edge.as_deref(),
                args.subdomain.as_deref(),
                args.inspect,
                args.inspect_addr.as_deref(),
                args.json,
                args.state_dir.as_deref(),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel_start(
    port: u16,
    protocol: &str,
    edge: Option<&str>,
    subdomain: Option<&str>,
    inspect: bool,
    inspect_addr: Option<&str>,
    json: bool,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let out = Output::new(json);
    if inspect && protocol != "https" && protocol != "http" {
        anyhow::bail!("--inspect requires --protocol https (or http in Direct mode)");
    }
    let client = ipc_or_err(state_dir).await?;
    let body = TunnelStartRequest {
        port,
        protocol: protocol.to_string(),
        edge: edge.map(str::to_string),
        subdomain: subdomain.map(str::to_string),
        inspect,
        inspect_addr: inspect_addr.map(str::to_string),
    };
    let info = client.tunnels_start(&body).await?;
    if out.json {
        return out.print_json(&info);
    }
    out.writeln(format!(
        "{} Forwarding  {} {} {}",
        out.green("✓"),
        out.cyan(&info.public_url),
        out.dim("→"),
        out.cyan(&format!("http://127.0.0.1:{port}"))
    ));
    if let Some(url) = &info.inspector_url {
        out.writeln(format!("  Inspector  {}", out.cyan(url)));
    }
    if info.relay == "local" {
        out.writeln(
            out.dim("  Direct mode: owns the mesh port - bind your app to 127.0.0.1 only."),
        );
    }
    if !inspect {
        return Ok(());
    }

    let inspector_url = info
        .inspector_url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:4040".into());
    out.writeln(out.dim("Streaming requests - Ctrl+C to stop"));
    out.writeln("");

    let stream = stream_inspect_console(&out, &inspector_url);
    let ctrl = tokio::signal::ctrl_c();
    tokio::pin!(stream);
    tokio::pin!(ctrl);
    tokio::select! {
        _ = &mut ctrl => {}
        r = &mut stream => {
            if let Err(e) = r {
                tracing::debug!(?e, "inspect console stream ended");
            }
        }
    }

    out.writeln("");
    out.writeln(out.dim("Stopping tunnel…"));
    let _ = client.tunnels_off(port).await;
    out.writeln(format!("{} Tunnel stopped", out.green("✓")));
    Ok(())
}

async fn stream_inspect_console(out: &Output, inspector_url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let list_url = format!("{}/api/requests", inspector_url.trim_end_matches('/'));
    let mut seen = std::collections::HashSet::<String>::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(400));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let resp = match client.get(&list_url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let Ok(items) = resp.json::<Vec<InspectLogRow>>().await else {
            continue;
        };
        for row in items {
            if !seen.insert(row.id.clone()) {
                continue;
            }
            let status = if row.status == 0 {
                "-".to_string()
            } else {
                row.status.to_string()
            };
            let status_painted = if row.status >= 400 || row.status == 0 {
                out.red(&status)
            } else if row.status >= 300 {
                out.dim(&status)
            } else {
                out.green(&status)
            };
            let method = format!("{:<7}", row.method);
            let path = truncate_path(&row.path, 48);
            out.writeln(format!(
                "  {} {} {}  {:>5}  {}",
                out.dim(
                    &row.started_at
                        .parse::<jiff::Timestamp>()
                        .map(|timestamp| timestamp.strftime("%H:%M:%S").to_string())
                        .unwrap_or_else(|_| row.started_at.clone()),
                ),
                out.bold(&method),
                path,
                status_painted,
                out.dim(&format!("{}ms", row.latency_ms)),
            ));
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectLogRow {
    id: String,
    started_at: String,
    method: String,
    path: String,
    status: u16,
    latency_ms: u64,
}

fn truncate_path(path: &str, max: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max {
        let mut s = path.to_string();
        while s.chars().count() < max {
            s.push(' ');
        }
        return s;
    }
    let mut s: String = chars.into_iter().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
}

async fn run_tunnel_status(json: bool, state_dir: Option<&str>) -> anyhow::Result<()> {
    let out = Output::new(json);
    let client = ipc_or_err(state_dir).await?;
    let resp = client.tunnels_list().await?;
    let tunnels = resp.tunnels;
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
    let client = ipc_or_err(state_dir).await?;
    let info = client.tunnels_off(port).await?;
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
pub async fn ensure_agent(state_dir: Option<&str>) -> anyhow::Result<TunnetClient> {
    ipc_or_err(state_dir).await
}

pub async fn run_up(state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client.data_plane_up().await?;
    println!("{}", resp.message);
    Ok(())
}

pub async fn run_down(state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = ipc_or_err(state_dir).await?;
    let resp = client.data_plane_down().await?;
    println!("{}", resp.message);
    Ok(())
}
