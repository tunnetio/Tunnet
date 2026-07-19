//! `tunnet send` CLI - P2P file transfer over the mesh.

use anyhow::Context;
use clap::{Args, Subcommand};
use tunnet_core::ipc::protocol::{IpcRequest, IpcResponse, format_ipc_error};

use crate::output::Output;

#[derive(Args, Debug)]
pub struct SendArgs {
    #[command(subcommand)]
    pub command: Option<SendCommand>,
    /// Path to send (when not using a subcommand).
    pub path: Option<String>,
    /// Target hostname, mesh IP, endpoint id, or `tag:name`.
    pub target: Option<String>,
    #[arg(short, long)]
    pub message: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SendCommand {
    /// Accept a pending inbound offer
    Accept(TransferIdArgs),
    /// Reject a pending inbound offer
    Reject(RejectArgs),
    /// List active / pending transfers
    List(ListArgs),
    /// Completed / failed / rejected history
    History(ListArgs),
    /// Show or update consent mode and inbox path
    Config(ConfigArgs),
}

#[derive(Args, Debug)]
pub struct TransferIdArgs {
    pub transfer_id: String,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct RejectArgs {
    pub transfer_id: String,
    #[arg(long)]
    pub reason: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Consent mode: auto_accept | prompt | deny
    #[arg(long)]
    pub consent: Option<String>,
    #[arg(long)]
    pub inbox: Option<String>,
    #[arg(long)]
    pub pin_blobs: Option<bool>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "TUNNET_STATE_DIR")]
    pub state_dir: Option<String>,
}

pub async fn run(args: SendArgs) -> anyhow::Result<()> {
    match args.command {
        Some(SendCommand::Accept(a)) => {
            let out = Output::new(a.json);
            let resp = ipc_req(
                &a.state_dir,
                IpcRequest::SendAccept {
                    transfer_id: a.transfer_id,
                },
            )
            .await?;
            print_resp(&out, resp)?;
        }
        Some(SendCommand::Reject(a)) => {
            let out = Output::new(a.json);
            let resp = ipc_req(
                &a.state_dir,
                IpcRequest::SendReject {
                    transfer_id: a.transfer_id,
                    reason: a.reason,
                },
            )
            .await?;
            print_resp(&out, resp)?;
        }
        Some(SendCommand::List(a)) => {
            let out = Output::new(a.json);
            let resp = ipc_req(&a.state_dir, IpcRequest::SendList).await?;
            print_resp(&out, resp)?;
        }
        Some(SendCommand::History(a)) => {
            let out = Output::new(a.json);
            let resp = ipc_req(&a.state_dir, IpcRequest::SendHistory).await?;
            print_resp(&out, resp)?;
        }
        Some(SendCommand::Config(a)) => {
            let out = Output::new(a.json);
            let resp = if a.consent.is_some() || a.inbox.is_some() || a.pin_blobs.is_some() {
                ipc_req(
                    &a.state_dir,
                    IpcRequest::SendSetConfig {
                        consent: a.consent,
                        inbox_path: a.inbox,
                        pin_blobs: a.pin_blobs,
                    },
                )
                .await?
            } else {
                ipc_req(&a.state_dir, IpcRequest::SendConfig).await?
            };
            print_resp(&out, resp)?;
        }
        None => {
            let path = args.path.context("usage: tunnet send <path> <target>")?;
            let target = args.target.context("usage: tunnet send <path> <target>")?;
            let out = Output::new(args.json);
            let resp = ipc_req(
                &args.state_dir,
                IpcRequest::SendFile {
                    path,
                    target,
                    message: args.message,
                },
            )
            .await?;
            print_resp(&out, resp)?;
        }
    }
    Ok(())
}

async fn ipc_req(state_dir: &Option<String>, req: IpcRequest) -> anyhow::Result<IpcResponse> {
    crate::cmds::ipc_or_err(state_dir.as_deref())
        .await?
        .request(req)
        .await
}

fn print_resp(out: &Output, resp: IpcResponse) -> anyhow::Result<()> {
    match resp {
        IpcResponse::Transfers { transfers } => {
            if out.json {
                return out.print_json(&transfers);
            }
            if transfers.is_empty() {
                println!("(none)");
                return Ok(());
            }
            for t in transfers {
                let peer = t.peer_hostname.as_deref().unwrap_or(&t.peer_endpoint_id);
                println!(
                    "{}\t{}\t{}\t{}\t{:.0}%\t{} → {}\t{}",
                    &t.transfer_id[..8.min(t.transfer_id.len())],
                    t.direction,
                    t.status,
                    t.file_name,
                    t.percent,
                    peer,
                    human_size(t.size),
                    t.inbox_path.unwrap_or_default()
                );
            }
        }
        IpcResponse::Transfer(t) => {
            if out.json {
                return out.print_json(&t);
            }
            println!(
                "{} {} {} ({}) {:.0}%",
                t.transfer_id, t.status, t.file_name, t.direction, t.percent
            );
        }
        IpcResponse::SendConfig(c) => {
            if out.json {
                return out.print_json(&c);
            }
            println!("consent:    {}", c.consent);
            println!("inbox:      {}", c.inbox_path);
            println!("pin_blobs:  {}", c.pin_blobs);
        }
        IpcResponse::Ok { message } => println!("{message}"),
        IpcResponse::Error { code, message } => {
            anyhow::bail!("{}", format_ipc_error(&code, &message));
        }
        other => {
            if out.json {
                return out.print_json(&other);
            }
            println!("{other:?}");
        }
    }
    Ok(())
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
