//! `tuntun ssh` - mesh SSH client + session/recording helpers.

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuntun_common::ssh::{encode_resize, escape_ssh_data};
use tuntun_core::ipc::protocol::{IpcRequest, IpcResponse};
use tuntun_core::ipc::transport;
use tuntun_core::ipc::{IpcClient, discover_network_id};

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
    #[arg(long, env = "TUNTUN_STATE_DIR")]
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
        #[arg(long, env = "TUNTUN_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// List saved session recordings
    Recordings {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, env = "TUNTUN_STATE_DIR")]
        state_dir: Option<String>,
    },
    /// Replay a recording in the terminal
    Play {
        session_id: String,
        #[arg(long, env = "TUNTUN_STATE_DIR")]
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
        None => {
            let target = args.target.context(
                "missing target - usage: tuntun ssh <target> | sessions | recordings | play <id>",
            )?;
            run_connect(target, args.user, args.command_args, args.state_dir).await
        }
    }
}

async fn ipc_request(state_dir: Option<&str>, req: IpcRequest) -> anyhow::Result<IpcResponse> {
    let (network_id, _) = discover_network_id(state_dir)?;
    let client = IpcClient::for_network(network_id);
    client.request(req).await
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
        IpcResponse::Error { message } => bail!("{message}"),
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
        IpcResponse::Error { message } => bail!("{message}"),
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
        IpcResponse::Error { message } => bail!("{message}"),
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
            // header
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
    let local_user = local_username();
    let user = user.unwrap_or_else(|| local_user.clone());
    let command = if command.is_empty() {
        None
    } else {
        Some(command.join(" "))
    };
    let interactive = command.is_none();

    let (cols, rows) = terminal_size();
    let term_type = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let env_vars = collect_env();

    let (network_id, _) = discover_network_id(state_dir.as_deref())?;
    let mut auth_token: Option<String> = None;

    // Up to 2 attempts: initial + one after re-auth proof.
    for attempt in 0..2 {
        let client = IpcClient::for_network(network_id);
        let stream = transport::connect(client.path()).await.with_context(|| {
            format!(
                "cannot connect to agent IPC at {} - is the agent running?",
                client.path().display()
            )
        })?;

        let (read, mut write) = stream.split();
        let req = IpcRequest::Ssh {
            target: target.clone(),
            user: user.clone(),
            local_user: local_user.clone(),
            term_type: term_type.clone(),
            width: cols,
            height: rows,
            env_vars: env_vars.clone(),
            auth_token: auth_token.clone(),
            command: command.clone(),
        };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;
        write.flush().await?;

        let mut reader = BufReader::new(read);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            bail!("agent closed IPC without a response");
        }
        let resp: IpcResponse = serde_json::from_str(line.trim())
            .with_context(|| format!("bad IPC response: {}", line.trim()))?;

        match resp {
            IpcResponse::Ready => {
                return splice_ssh_session(reader, write, interactive).await;
            }
            IpcResponse::SshReauthRequired {
                reauth_url,
                challenge_token,
                message,
            } => {
                if attempt > 0 {
                    bail!("{message} (re-authentication still required)");
                }
                eprintln!("{message}");
                if reauth_url.is_empty() || challenge_token.is_empty() {
                    bail!("re-authentication required but no challenge URL was provided");
                }
                eprintln!("Opening browser... ({reauth_url})");
                open_browser(&reauth_url)?;
                eprint!("Waiting for authentication...");
                let proof = wait_for_proof(state_dir.as_deref(), &challenge_token).await?;
                eprintln!(" ✓");
                auth_token = Some(proof);
                continue;
            }
            IpcResponse::Error { message } => {
                eprintln!("{message}");
                std::process::exit(1);
            }
            other => bail!("unexpected IPC response: {other:?}"),
        }
    }
    bail!("re-authentication failed");
}

async fn wait_for_proof(state_dir: Option<&str>, challenge_token: &str) -> anyhow::Result<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    loop {
        if std::time::Instant::now() > deadline {
            bail!("timed out waiting for re-authentication");
        }
        let resp = ipc_request(
            state_dir,
            IpcRequest::SshAuthPoll {
                challenge_token: challenge_token.to_string(),
            },
        )
        .await?;
        match resp {
            IpcResponse::SshAuthPoll {
                status,
                proof_token,
            } => match status.as_str() {
                "ready" => {
                    return proof_token.context("missing proof token");
                }
                "pending" => {
                    eprint!(".");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                "expired" => bail!("re-authentication challenge expired"),
                other => bail!("re-authentication failed ({other})"),
            },
            IpcResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected poll response: {other:?}"),
        }
    }
}

fn open_browser(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = url;
        bail!("cannot open browser on this platform");
    }
}

async fn splice_ssh_session<R, W>(
    reader: BufReader<R>,
    mut write: W,
    interactive: bool,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _raw_guard = if interactive {
        Some(RawModeGuard::enter()?)
    } else {
        None
    };

    let mut ipc_read = reader.into_inner();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let stdin_task = {
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let escaped = escape_ssh_data(&buf[..n]);
                if out_tx.send(escaped).await.is_err() {
                    break;
                }
            }
        })
    };

    let resize_task = tokio::spawn(async move {
        if !interactive {
            return;
        }
        loop {
            wait_for_resize().await;
            let (cols, rows) = terminal_size();
            if out_tx
                .send(encode_resize(cols, rows).to_vec())
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let writer_task = tokio::spawn(async move {
        while let Some(chunk) = out_rx.recv().await {
            if write.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = write.flush().await;
        }
        let _ = write.shutdown().await;
    });

    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match ipc_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if stdout.write_all(&buf[..n]).await.is_err() {
            break;
        }
        let _ = stdout.flush().await;
    }

    stdin_task.abort();
    resize_task.abort();
    let _ = writer_task.await;
    Ok(())
}

fn local_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into())
}

fn collect_env() -> Vec<(String, String)> {
    let keys = [
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "COLORTERM",
        "TERM_PROGRAM",
        "TERM_PROGRAM_VERSION",
    ];
    keys.iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v)))
        .collect()
}

fn terminal_size() -> (u16, u16) {
    #[cfg(unix)]
    {
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
                && ws.ws_col > 0
                && ws.ws_row > 0
            {
                return (ws.ws_col, ws.ws_row);
            }
        }
    }
    (120, 40)
}

struct RawModeGuard {
    #[cfg(unix)]
    original: libc::termios,
}

impl RawModeGuard {
    fn enter() -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            unsafe {
                let mut term: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
                    bail!("tcgetattr failed");
                }
                let original = term;
                libc::cfmakeraw(&mut term);
                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) != 0 {
                    bail!("tcsetattr failed");
                }
                Ok(Self { original })
            }
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

async fn wait_for_resize() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::window_change()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => {
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}
