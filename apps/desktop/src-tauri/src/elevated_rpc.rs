//! Privileged ops via an elevated copy of this process.
//!
//! Lifecycle Local API calls and Windows service control need an elevated
//! peer / process. The GUI stays unelevated; we ShellExecute ourselves with
//! UAC, run the work, write a JSON result, and exit - before Tauri starts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tunnet_client::TunnetClient;
use tunnet_common::local_api::{
    LocalEnrollRequest, NetworkCreateRequest, NetworkJoinRequest, NetworkLeaveRequest, OkResponse,
    ResetRequest,
};

pub const FLAG: &str = "--tunnet-elevated-rpc";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ElevatedOp {
    NetworkCreate { body: NetworkCreateRequest },
    NetworkJoin { body: NetworkJoinRequest },
    Enroll { body: LocalEnrollRequest },
    NetworkLeave { body: NetworkLeaveRequest },
    Reset { body: ResetRequest },
    ServiceStart,
    ServiceStop,
    ServiceRestart,
    CoreUpdateInstall,
}

#[derive(Debug, Serialize, Deserialize)]
struct ElevatedResult {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn maybe_run_worker() {
    let args: Vec<String> = std::env::args().collect();
    let Some(idx) = args.iter().position(|a| a == FLAG) else {
        return;
    };
    let req = args.get(idx + 1).map(PathBuf::from);
    let resp = args.get(idx + 2).map(PathBuf::from);
    let (Some(req), Some(resp)) = (req, resp) else {
        eprintln!("{FLAG} requires <request.json> <response.json>");
        std::process::exit(2);
    };

    let code = match run_worker(&req, &resp) {
        Ok(()) => 0,
        Err(e) => {
            let _ = write_result(
                &resp,
                &ElevatedResult {
                    ok: false,
                    message: None,
                    error: Some(format!("{e:#}")),
                },
            );
            1
        }
    };
    std::process::exit(code);
}

fn run_worker(req_path: &Path, resp_path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(req_path)?;
    let op: ElevatedOp = serde_json::from_str(&raw)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match rt.block_on(execute(op)) {
        Ok(ok) => {
            write_result(
                resp_path,
                &ElevatedResult {
                    ok: true,
                    message: Some(ok.message),
                    error: None,
                },
            )?;
            Ok(())
        }
        Err(e) => {
            let _ = write_result(
                resp_path,
                &ElevatedResult {
                    ok: false,
                    message: None,
                    error: Some(e.to_string()),
                },
            );
            Err(e)
        }
    }
}

async fn execute(op: ElevatedOp) -> anyhow::Result<OkResponse> {
    match op {
        ElevatedOp::ServiceStart => {
            tunnet_service::start(None)?;
            Ok(OkResponse {
                message: "Service started".into(),
            })
        }
        ElevatedOp::ServiceStop => {
            tunnet_service::stop(None)?;
            Ok(OkResponse {
                message: "Service stopped".into(),
            })
        }
        ElevatedOp::ServiceRestart => {
            tunnet_service::restart(None)?;
            Ok(OkResponse {
                message: "Service restarted".into(),
            })
        }
        ElevatedOp::CoreUpdateInstall => {
            TunnetClient::connect()
                .update(&tunnet_common::local_api::UpdateRequest {
                    force: false,
                    restart: false,
                    version: None,
                })
                .await?;
            Ok(OkResponse {
                message: "Tunnet Core update started".into(),
            })
        }
        ElevatedOp::NetworkCreate { body } => TunnetClient::connect().network_create(&body).await,
        ElevatedOp::NetworkJoin { body } => TunnetClient::connect().network_join(&body).await,
        ElevatedOp::Enroll { body } => TunnetClient::connect().enroll(&body).await,
        ElevatedOp::NetworkLeave { body } => TunnetClient::connect().network_leave(&body).await,
        // Do reset in-process (not via daemon IPC): stop_for_reset would kill the
        // daemon mid-request if we called TunnetClient::reset().
        ElevatedOp::Reset { body } => reset_device(body).await,
    }
}

async fn reset_device(body: ResetRequest) -> anyhow::Result<OkResponse> {
    if !body.yes {
        return Ok(OkResponse {
            message: "confirmation required; set yes=true to wipe".into(),
        });
    }

    let targets: Vec<PathBuf> = if let Ok(env_dir) = std::env::var("TUNNET_STATE_DIR") {
        let env_dir = PathBuf::from(env_dir);
        let system = tunnet_service::system_state_dir();
        if env_dir == system {
            vec![system]
        } else {
            vec![system, env_dir]
        }
    } else {
        vec![tunnet_service::system_state_dir()]
    };

    match tunnet_service::stop_for_reset() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("warning: could not stop service before reset: {e:#}");
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut wiped_any = false;
    for dir in &targets {
        if !dir.exists() {
            continue;
        }
        tunnet_service::wipe_state_dir(dir)?;
        wiped_any = true;
    }

    if tunnet_service::probe().installed {
        tunnet_service::start(None)?;
    }

    Ok(OkResponse {
        message: if wiped_any {
            "state wiped".into()
        } else {
            "nothing to wipe".into()
        },
    })
}

fn write_result(path: &Path, result: &ElevatedResult) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_vec_pretty(result)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Run a privileged op: directly if already elevated, otherwise via UAC worker.
pub async fn run_elevated_op(op: ElevatedOp) -> Result<OkResponse, String> {
    if tunnet_service::is_admin() {
        return execute(op).await.map_err(|e| e.to_string());
    }

    tokio::task::spawn_blocking(move || elevate_and_run(op))
        .await
        .map_err(|e| e.to_string())?
}

fn elevate_and_run(op: ElevatedOp) -> Result<OkResponse, String> {
    #[cfg(windows)]
    {
        let stamp = std::process::id();
        let req_path = std::env::temp_dir().join(format!("tunnet-desktop-elev-req-{stamp}.json"));
        let resp_path = std::env::temp_dir().join(format!("tunnet-desktop-elev-resp-{stamp}.json"));

        let req_json = serde_json::to_vec_pretty(&op).map_err(|e| e.to_string())?;
        std::fs::write(&req_path, req_json).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&resp_path);

        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exit = tunnet_service::run_elevated(
            &exe,
            &[
                FLAG,
                req_path.to_string_lossy().as_ref(),
                resp_path.to_string_lossy().as_ref(),
            ],
        )
        .map_err(|e| e.to_string())?;

        let result = read_result(&resp_path);
        let _ = std::fs::remove_file(&req_path);
        let _ = std::fs::remove_file(&resp_path);

        match result {
            Ok(r) if r.ok => Ok(OkResponse {
                message: r.message.unwrap_or_else(|| "ok".into()),
            }),
            Ok(r) => Err(r
                .error
                .unwrap_or_else(|| format!("elevated operation failed (exit {exit})"))),
            Err(e) if exit != 0 => Err(format!("elevated operation failed (exit {exit}): {e}")),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = op;
        Err(
            "this operation needs root. Re-run Tunnet Desktop with sudo, or use an elevated session."
                .into(),
        )
    }
}

#[cfg(windows)]
fn read_result(path: &Path) -> Result<ElevatedResult, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("elevated worker did not write a result ({e})"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid elevated result: {e}"))
}
