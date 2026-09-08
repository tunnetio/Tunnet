//! Local API helpers used by in-process bootstrap (enroll / create / join).

use anyhow::Context;
use tunnet_client::{ApiErrorCode, TunnetClient, format_api_error};

/// Connect to the Local API, or return a clear "daemon not running" error.
pub async fn ipc_or_err(_state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = TunnetClient::connect();
    if !tunnet_client::endpoint_reachable(client.path()).await {
        anyhow::bail!("{}", format_api_error(&ApiErrorCode::DaemonNotRunning, ""));
    }
    Ok(())
}

pub async fn wait_until_agent(state_dir: Option<&str>, secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last_err = None;
    while tokio::time::Instant::now() < deadline {
        match ipc_or_err(state_dir).await {
            Ok(()) => return Ok(()),
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

fn running_as_service() -> bool {
    std::env::var_os("TUNNET_SERVICE_MODE").is_some()
        || std::env::var_os("NOTIFY_SOCKET").is_some()
        || std::env::var_os("INVOCATION_ID").is_some()
}

pub async fn finish_after_config(
    state_dir: Option<&str>,
    needs_process_restart: bool,
) -> anyhow::Result<()> {
    if !needs_process_restart {
        tracing::info!("config written; daemon will load the new state");
        return Ok(());
    }

    if running_as_service() {
        let dir = state_dir.map(str::to_owned);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            match tokio::task::spawn_blocking(move || {
                tunnet_service::reload_after_config(dir.as_deref())
            })
            .await
            {
                Ok(Err(e)) => tracing::error!(?e, "deferred service reload failed"),
                Err(e) => tracing::error!(?e, "deferred service reload task failed"),
                Ok(Ok(())) => {}
            }
        });
        tracing::info!("config written; deferred service reload scheduled");
        return Ok(());
    }

    crate::service::reload_after_config(state_dir)?;
    if let Err(e) = wait_until_agent(state_dir, 20).await {
        println!("Note: {e}");
    } else {
        println!("Agent is up.");
    }
    Ok(())
}
