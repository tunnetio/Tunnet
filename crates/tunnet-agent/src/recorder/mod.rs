//! Local SSH session recorder (asciinema v2 + SQLite index).

mod store;

use std::sync::Arc;

use iroh::endpoint::Connection;
use tunnet_common::ws::ClientMsg;
use tunnet_core::SignedClient;
use tunnet_core::recording::read_meta;

pub use store::{ActiveCastWriter, FinalizedCast, RecordingStore};

/// Accept inbound recording streams and persist `.cast` files.
pub async fn serve_recording_connection(
    conn: Connection,
    store: Arc<RecordingStore>,
    cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    signed: Option<SignedClient>,
    self_endpoint_id: String,
) {
    let peer = conn.remote_id();
    let peer_hex = format!("{peer}");
    loop {
        let (_send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(%peer_hex, ?e, "recording accept_bi closed");
                break;
            }
        };
        let store = store.clone();
        let cp_tx = cp_tx.clone();
        let signed = signed.clone();
        let self_endpoint_id = self_endpoint_id.clone();
        let peer_hex = peer_hex.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_recording_stream(&mut recv, store, cp_tx, signed, self_endpoint_id, peer_hex)
                    .await
            {
                tracing::warn!(?e, "recording stream failed");
            }
        });
    }
}

async fn handle_recording_stream(
    recv: &mut iroh::endpoint::RecvStream,
    store: Arc<RecordingStore>,
    cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    signed: Option<SignedClient>,
    self_endpoint_id: String,
    src_peer: String,
) -> anyhow::Result<()> {
    let meta = read_meta(recv).await?;
    tracing::info!(
        session = %meta.session_id,
        from = %src_peer,
        user = %meta.user,
        "recording stream accepted"
    );

    let started = std::time::Instant::now();
    let mut sink = store.begin_stream_sink(&meta)?;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = match recv.read(&mut buf).await? {
            Some(n) => n,
            None => break,
        };
        sink.write_all(&buf[..n])?;
    }
    let (meta, finalized) = sink.finish()?;
    let duration_ms = started.elapsed().as_millis() as u64;

    store.index_finished(
        &meta,
        &finalized.path,
        finalized.byte_size,
        &finalized.sha256_hex,
        duration_ms,
    )?;

    if let Some(tx) = &cp_tx {
        let _ = tx.try_send(ClientMsg::SshRecordingSaved {
            session_id: meta.session_id.clone(),
            recorder_endpoint_id: self_endpoint_id.clone(),
            duration_ms: Some(duration_ms),
            byte_size: finalized.byte_size,
            content_sha256: finalized.sha256_hex.clone(),
        });
    }

    if let Some(client) = &signed {
        let cast_text = std::fs::read_to_string(&finalized.path)?;
        if let Err(e) = client
            .upload_ssh_recording(&meta.session_id, &cast_text, &finalized.sha256_hex)
            .await
        {
            tracing::warn!(?e, session = %meta.session_id, "failed to upload recording to CP");
        }
    }

    Ok(())
}
