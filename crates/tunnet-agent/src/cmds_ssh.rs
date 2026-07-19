//! `tunnet ssh` - OpenSSH wrapper + session/recording helpers.

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use tokio::io::AsyncWriteExt;
use tunnet_core::ipc::protocol::{IpcRequest, IpcResponse, format_ipc_error};
use tunnet_core::state::StatePaths;

use crate::ssh::known_hosts_path;

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SshArgs {
    #[command(subcommand)]
    pub command: Option<SshSubcommand>,
    /// Target hostname, mesh IP, or endpoint id (when not using a subcommand)
    pub target: Option<String>,
    /// Remote user (default: local username)
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    /// Command to run non-interactively (after `--`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command_args: Vec<String>,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct SshKeyscanArgs {
    /// Targets (hostname, mesh IP, or endpoint id). Empty = all peers with a host key.
    pub targets: Vec<String>,
    /// Also write entries into the Tunnet known_hosts file
    #[arg(short = 'f', long)]
    pub write: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct SshProxyArgs {
    /// Hostname, mesh IP, or `*.tunnet` name (OpenSSH `%h`)
    pub host: String,
    /// TCP port (OpenSSH `%p`, usually 22)
    pub port: u16,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SshSubcommand {
    /// List SSH sessions visible on this network
    Sessions {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// List saved session recordings
    Recordings {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// Replay a recording in the terminal
    Play {
        session_id: String,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// Write / update a `Host *.tunnet` block in `~/.ssh/config`
    Config {
        /// Path to OpenSSH config (default: ~/.ssh/config)
        #[arg(long)]
        path: Option<String>,
        #[arg(long, env = "TUNNET_STATE_DIR")]
        state_dir: Option<String>,
    },
}

pub async fn run_ssh(args: SshArgs) -> anyhow::Result<()> {
    match args.command {
        Some(SshSubcommand::Sessions {
            limit,
            status,
            state_dir,
        }) => run_sessions(limit, status, state_dir.or(args.state_dir)).await,
        Some(SshSubcommand::Recordings { limit, state_dir }) => {
            run_recordings(limit, state_dir.or(args.state_dir)).await
        }
        Some(SshSubcommand::Play {
            session_id,
            state_dir,
        }) => run_play(session_id, state_dir.or(args.state_dir)).await,
        Some(SshSubcommand::Config { path, state_dir }) => {
            run_ssh_config(path, state_dir.or(args.state_dir)).await
        }
        None => {
            let target = args.target.context(
                "missing target - usage: tunnet ssh <target> | sessions | recordings | play <id> | config",
            )?;
            run_connect(target, args.user, args.command_args, args.state_dir).await
        }
    }
}

async fn ipc_request(_state_dir: Option<&str>, req: IpcRequest) -> anyhow::Result<IpcResponse> {
    crate::cmds::ipc_or_err(_state_dir)
        .await?
        .request(req)
        .await
}

async fn run_sessions(
    limit: u32,
    status: Option<String>,
    state_dir: Option<String>,
) -> anyhow::Result<()> {
    let resp = ipc_request(
        state_dir.as_deref(),
        IpcRequest::SshSessions { limit, status },
    )
    .await?;
    match resp {
        IpcResponse::SshSessions { sessions } => {
            if sessions.is_empty() {
                println!("No SSH sessions.");
                return Ok(());
            }
            println!(
                "{:<38} {:<18} {:<18} {:<10} {:<8} STARTED",
                "SESSION", "FROM", "TO", "USER", "STATUS"
            );
            for s in sessions {
                let from = s
                    .src_hostname
                    .unwrap_or_else(|| short_id(&s.src_endpoint_id));
                let to = s
                    .dst_hostname
                    .unwrap_or_else(|| short_id(&s.dst_endpoint_id));
                println!(
                    "{:<38} {:<18} {:<18} {:<10} {:<8} {}",
                    s.id, from, to, s.target_user, s.status, s.started_at
                );
            }
            Ok(())
        }
        IpcResponse::Error { code, message } => bail!("{}", format_ipc_error(&code, &message)),
        other => bail!("unexpected IPC response: {other:?}"),
    }
}

async fn run_recordings(limit: u32, state_dir: Option<String>) -> anyhow::Result<()> {
    let resp = ipc_request(state_dir.as_deref(), IpcRequest::SshRecordings { limit }).await?;
    match resp {
        IpcResponse::SshRecordings { recordings } => {
            if recordings.is_empty() {
                println!("No recordings.");
                return Ok(());
            }
            println!(
                "{:<38} {:<12} {:<18} {:>10} CREATED",
                "SESSION", "USER", "MACHINE", "BYTES"
            );
            for r in recordings {
                let machine = r.dst_hostname.unwrap_or_else(|| short_id(&r.session_id));
                let user = r.target_user.unwrap_or_else(|| "-".into());
                println!(
                    "{:<38} {:<12} {:<18} {:>10} {}",
                    r.session_id, user, machine, r.byte_size, r.created_at
                );
            }
            Ok(())
        }
        IpcResponse::Error { code, message } => bail!("{}", format_ipc_error(&code, &message)),
        other => bail!("unexpected IPC response: {other:?}"),
    }
}

async fn run_play(session_id: String, state_dir: Option<String>) -> anyhow::Result<()> {
    let resp = ipc_request(
        state_dir.as_deref(),
        IpcRequest::SshPlay {
            session_id: session_id.clone(),
        },
    )
    .await?;
    let cast = match resp {
        IpcResponse::SshCast { cast_text, .. } => cast_text,
        IpcResponse::Error { code, message } => bail!("{}", format_ipc_error(&code, &message)),
        other => bail!("unexpected IPC response: {other:?}"),
    };
    play_cast(&cast).await
}

async fn play_cast(cast_text: &str) -> anyhow::Result<()> {
    let mut stdout = tokio::io::stdout();
    let mut start = None::<std::time::Instant>;
    for line in cast_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("version").is_some() {
            continue;
        }
        let arr = match v.as_array() {
            Some(a) if a.len() >= 3 => a,
            _ => continue,
        };
        let t = arr[0].as_f64().unwrap_or(0.0);
        let kind = arr[1].as_str().unwrap_or("");
        if kind != "o" {
            continue;
        }
        let data = arr[2].as_str().unwrap_or("");
        let elapsed = start.get_or_insert_with(std::time::Instant::now).elapsed();
        let target = std::time::Duration::from_secs_f64(t.max(0.0));
        if target > elapsed {
            tokio::time::sleep(target - elapsed).await;
        }
        stdout.write_all(data.as_bytes()).await?;
        let _ = stdout.flush().await;
    }
    stdout.write_all(b"\n").await?;
    Ok(())
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        id[..8].to_string()
    } else {
        id.to_string()
    }
}

async fn run_connect(
    target: String,
    user: Option<String>,
    command: Vec<String>,
    state_dir: Option<String>,
) -> anyhow::Result<()> {
    let paths = StatePaths::resolve(state_dir.as_deref());
    let known_hosts = known_hosts_path(&paths.dir);
    if let Some(parent) = known_hosts.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let host = args_target_for_ssh(&target);
    let user = user.unwrap_or_else(local_username);
    let proxy = proxy_command_string(state_dir.as_deref())?;

    let mut args = vec![
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        format!("ProxyCommand={proxy}"),
        "-o".into(),
        "PreferredAuthentications=none,keyboard-interactive".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-l".into(),
        user,
        host,
    ];
    if !command.is_empty() {
        args.push("--".into());
        args.extend(command);
    }

    let status = std::process::Command::new("ssh")
        .args(&args)
        .status()
        .context("failed to exec ssh - is OpenSSH client installed?")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// OpenSSH ProxyCommand: splice stdin/stdout to TCP `host:port` over the mesh TUN.
pub async fn run_ssh_proxy(args: SshProxyArgs) -> anyhow::Result<()> {
    let ip = resolve_host(&args.host).await.with_context(|| {
        format!(
            "cannot resolve mesh host `{}` - is the agent running?",
            args.host
        )
    })?;
    let addr = format!("{}:{}", ip, args.port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| {
            format!("cannot connect to {addr} over the mesh - is the data plane up (`tunnet up`)?")
        })?;
    let _ = stream.set_nodelay(true);

    let (mut reader, mut writer) = stream.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let upload = async {
        tokio::io::copy(&mut stdin, &mut writer).await?;
        let _ = writer.shutdown().await;
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        tokio::io::copy(&mut reader, &mut stdout).await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = upload => r?,
        r = download => r?,
    }
    Ok(())
}

const SSH_CONFIG_BEGIN: &str = "# BEGIN TUNNET";
const SSH_CONFIG_END: &str = "# END TUNNET";

async fn run_ssh_config(path: Option<String>, state_dir: Option<String>) -> anyhow::Result<()> {
    let paths = StatePaths::resolve(state_dir.as_deref());
    let known_hosts = known_hosts_path(&paths.dir);
    if let Some(parent) = known_hosts.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let config_path = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => default_ssh_config_path()?,
    };
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let block = ssh_config_block(&known_hosts, state_dir.as_deref())?;
    let existing = if config_path.is_file() {
        std::fs::read_to_string(&config_path)
            .with_context(|| format!("read {}", config_path.display()))?
    } else {
        String::new()
    };
    let updated = upsert_marked_block(&existing, SSH_CONFIG_BEGIN, SSH_CONFIG_END, &block);
    std::fs::write(&config_path, updated)
        .with_context(|| format!("write {}", config_path.display()))?;
    println!("Wrote Tunnet SSH config block to {}", config_path.display());
    println!("You can now: ssh user@hostname.tunnet");
    Ok(())
}

fn proxy_command_string(state_dir: Option<&str>) -> anyhow::Result<String> {
    let exe = std::env::current_exe().context("resolve tunnet binary path")?;
    let exe = exe.display().to_string().replace('\\', "/");
    let mut cmd = format!("\"{exe}\" ssh-proxy %h %p");
    if let Some(dir) = state_dir.filter(|d| !d.is_empty()) {
        let dir = dir.replace('\\', "/");
        cmd.push_str(&format!(" --state-dir \"{dir}\""));
    }
    Ok(cmd)
}

/// Prefer `name.tunnet` so OpenSSH HostKeyChecking matches known_hosts FQDNs.
fn args_target_for_ssh(target: &str) -> String {
    if target.parse::<std::net::Ipv4Addr>().is_ok() {
        return target.to_string();
    }
    if target.contains('.') {
        return target.to_string();
    }
    format!("{target}.tunnet")
}

fn ssh_config_block(
    known_hosts: &std::path::Path,
    state_dir: Option<&str>,
) -> anyhow::Result<String> {
    let proxy = proxy_command_string(state_dir)?;
    let kh = known_hosts.display().to_string().replace('\\', "/");
    Ok(format!(
        "{SSH_CONFIG_BEGIN}\n\
Host *.tunnet\n\
\tProxyCommand {proxy}\n\
\tUserKnownHostsFile {kh}\n\
\tStrictHostKeyChecking yes\n\
\tPreferredAuthentications none,keyboard-interactive\n\
\tPubkeyAuthentication no\n\
\tPasswordAuthentication no\n\
{SSH_CONFIG_END}\n"
    ))
}

fn upsert_marked_block(existing: &str, begin: &str, end: &str, block: &str) -> String {
    if let Some(start) = existing.find(begin) {
        let after_start = &existing[start..];
        if let Some(rel_end) = after_start.find(end) {
            let end_idx = start + rel_end + end.len();
            let mut end_idx = end_idx;
            if existing[end_idx..].starts_with('\r') {
                end_idx += 1;
            }
            if existing[end_idx..].starts_with('\n') {
                end_idx += 1;
            }
            let mut out = String::with_capacity(existing.len() + block.len());
            out.push_str(&existing[..start]);
            out.push_str(block);
            if !block.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&existing[end_idx..]);
            return out;
        }
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    if !block.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn default_ssh_config_path() -> anyhow::Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let home = std::env::var("USERPROFILE").context("USERPROFILE not set")?;
        Ok(std::path::PathBuf::from(home).join(".ssh").join("config"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(std::path::PathBuf::from(home).join(".ssh").join("config"))
    }
}

async fn resolve_host(target: &str) -> Option<String> {
    if target.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(target.to_string());
    }
    let resp = ipc_request(None, IpcRequest::Status { peers: true })
        .await
        .ok()?;
    let IpcResponse::Status(status) = resp else {
        return None;
    };
    let peers = status.peers.unwrap_or_default();
    let needle = target.trim_end_matches(".tunnet");
    for peer in peers {
        if peer.hostname.eq_ignore_ascii_case(needle)
            || peer.hostname.eq_ignore_ascii_case(target)
            || peer.endpoint_id.eq_ignore_ascii_case(target)
        {
            if !peer.ip.is_empty() {
                return Some(peer.ip);
            }
            return Some(peer.hostname);
        }
    }
    None
}

fn local_username() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "user".into())
    }
    #[cfg(unix)]
    {
        std::env::var("USER").unwrap_or_else(|_| "user".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "user".into()
    }
}

pub async fn run_ssh_keyscan(args: SshKeyscanArgs) -> anyhow::Result<()> {
    let paths = StatePaths::resolve(args.state_dir.as_deref());
    let resp = ipc_request(
        args.state_dir.as_deref(),
        IpcRequest::Status { peers: true },
    )
    .await?;
    let IpcResponse::Status(status) = resp else {
        bail!("unexpected IPC response: {resp:?}");
    };
    let peers = status.peers.unwrap_or_default();
    let suffix = "tunnet".to_string();

    let selected: Vec<_> = if args.targets.is_empty() {
        peers
            .into_iter()
            .filter(|p| {
                p.ssh_host_key
                    .as_ref()
                    .is_some_and(|k| !k.trim().is_empty())
            })
            .collect()
    } else {
        let mut out = Vec::new();
        for target in &args.targets {
            let needle = target.trim_end_matches(".tunnet");
            let peer = peers.iter().find(|p| {
                p.hostname.eq_ignore_ascii_case(needle)
                    || p.hostname.eq_ignore_ascii_case(target)
                    || p.endpoint_id.eq_ignore_ascii_case(target)
                    || p.ip.eq_ignore_ascii_case(target)
            });
            match peer {
                Some(p) => out.push(p.clone()),
                None => bail!("no peer matches {target}"),
            }
        }
        out
    };

    if selected.is_empty() {
        bail!("no SSH host keys available yet (peers must be online and publishing keys)");
    }

    let mut entries = Vec::new();
    for p in &selected {
        let Some(key) = p.ssh_host_key.as_deref().filter(|k| !k.trim().is_empty()) else {
            eprintln!("# {target}: no host key advertised", target = p.hostname);
            continue;
        };
        let fqdn = format!("{}.{}", p.hostname, suffix.trim_matches('.'));
        let hosts = [p.ip.as_str(), p.hostname.as_str(), fqdn.as_str()];
        if let Some(line) = tunnet_core::known_hosts::known_hosts_line(&hosts, key) {
            println!("{line}");
            entries.push((hosts.map(|s| s.to_string()), key.to_string()));
        }
    }

    if args.write {
        for (hosts, key) in entries {
            let host_refs: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();
            tunnet_core::known_hosts::upsert_known_hosts_entry(&paths.dir, &host_refs, &key)?;
        }
        eprintln!(
            "# wrote {} entr{} to {}",
            selected.len(),
            if selected.len() == 1 { "y" } else { "ies" },
            known_hosts_path(&paths.dir).display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_replaces_existing_block() {
        let existing =
            "Host *\n\tForwardAgent yes\n\n# BEGIN TUNNET\nold\n# END TUNNET\n\nHost other\n";
        let block = "# BEGIN TUNNET\nnew\n# END TUNNET\n";
        let out = upsert_marked_block(existing, SSH_CONFIG_BEGIN, SSH_CONFIG_END, block);
        assert!(out.contains("new"));
        assert!(!out.contains("old"));
        assert!(out.contains("ForwardAgent yes"));
        assert!(out.contains("Host other"));
    }

    #[test]
    fn upsert_appends_when_missing() {
        let existing = "Host *\n";
        let block = "# BEGIN TUNNET\nnew\n# END TUNNET\n";
        let out = upsert_marked_block(existing, SSH_CONFIG_BEGIN, SSH_CONFIG_END, block);
        assert!(out.ends_with("# END TUNNET\n") || out.contains("# END TUNNET\n"));
        assert!(out.starts_with("Host *\n"));
    }

    #[test]
    fn args_target_adds_tunnet_suffix() {
        assert_eq!(args_target_for_ssh("db"), "db.tunnet");
        assert_eq!(args_target_for_ssh("db.tunnet"), "db.tunnet");
        assert_eq!(args_target_for_ssh("10.0.0.1"), "10.0.0.1");
    }
}
