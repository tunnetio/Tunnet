//! Tee PTY output to a session recorder (local file or remote mesh stream).

use std::time::{Duration, Instant};

use iroh::EndpointId;
use tokio::sync::mpsc;
use tunnet_common::policy::Selector;
use tunnet_common::recording::{RecordingMeta, asciinema_header_line, asciinema_output_event};
use tunnet_core::recording::dial_recording;
use tunnet_core::{AclEngine, ConnPool, RoutingTable};

use crate::recorder::{ActiveCastWriter, FinalizedCast, RecordingStore};

pub const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
pub const FLUSH_BYTES: usize = 4 * 1024;
pub const MAX_BUFFER: usize = 1024 * 1024;

pub enum RecorderTarget {
    Local,
    Remote(EndpointId),
}

/// Resolve where recordings should be sent for a policy selector.
pub fn resolve_recorder_target(
    routes: &RoutingTable,
    acl: &AclEngine,
    selector: Option<&Selector>,
) -> Option<RecorderTarget> {
    let self_id = acl.self_id.load();
    let sel = selector
        .cloned()
        .unwrap_or(Selector::Tag("recorder".into()));
    match sel {
        Selector::Any => Some(RecorderTarget::Local),
        Selector::Endpoint(id) => {
            if id.eq_ignore_ascii_case(&self_id.endpoint_hex) {
                Some(RecorderTarget::Local)
            } else {
                routes
                    .lookup_endpoint(&id)
                    .map(|p| RecorderTarget::Remote(p.endpoint))
            }
        }
        Selector::Tag(tag) => {
            if self_id.tags.iter().any(|t| t == &tag) {
                return Some(RecorderTarget::Local);
            }
            routes.peers().into_iter().find_map(|p| {
                if p.tags.iter().any(|t| t == &tag) {
                    Some(RecorderTarget::Remote(p.endpoint))
                } else {
                    None
                }
            })
        }
        Selector::Network(_) | Selector::Cidr(_) => None,
        Selector::User(id) => {
            let marker = format!("user:{id}");
            if self_id
                .tags
                .iter()
                .any(|t| t == &marker || t.eq_ignore_ascii_case(id.as_str()))
            {
                return Some(RecorderTarget::Local);
            }
            routes.peers().into_iter().find_map(|p| {
                if p.tags
                    .iter()
                    .any(|t| t == &marker || t.eq_ignore_ascii_case(id.as_str()))
                {
                    Some(RecorderTarget::Remote(p.endpoint))
                } else {
                    None
                }
            })
        }
    }
}

pub enum RecordingTee {
    Local(ActiveCastWriter),
    Remote {
        tx: mpsc::Sender<Vec<u8>>,
        start: Instant,
        meta: RecordingMeta,
        header_sent: bool,
    },
}

impl RecordingTee {
    pub fn local(store: &RecordingStore, meta: &RecordingMeta) -> anyhow::Result<Self> {
        Ok(Self::Local(store.begin(meta)?))
    }

    pub async fn remote(
        pool: &ConnPool,
        peer: EndpointId,
        meta: RecordingMeta,
    ) -> anyhow::Result<Self> {
        let (mut send, _recv) = dial_recording(pool, peer, &meta).await?;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut pending = Vec::new();
            let mut last_flush = Instant::now();
            let mut total_buffered = 0usize;
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(chunk) => {
                                pending.extend_from_slice(&chunk);
                                total_buffered += chunk.len();
                                if pending.len() >= FLUSH_BYTES || last_flush.elapsed() >= FLUSH_INTERVAL {
                                    if send.write_all(&pending).await.is_err() {
                                        break;
                                    }
                                    pending.clear();
                                    last_flush = Instant::now();
                                    total_buffered = 0;
                                }
                                if total_buffered > MAX_BUFFER {
                                    tracing::warn!("recording remote buffer overflow; dropping");
                                    break;
                                }
                            }
                            None => {
                                if !pending.is_empty() {
                                    let _ = send.write_all(&pending).await;
                                }
                                let _ = send.finish();
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(FLUSH_INTERVAL) => {
                        if !pending.is_empty() {
                            if send.write_all(&pending).await.is_err() {
                                break;
                            }
                            pending.clear();
                            last_flush = Instant::now();
                            total_buffered = 0;
                        }
                    }
                }
            }
        });
        Ok(Self::Remote {
            tx,
            start: Instant::now(),
            meta,
            header_sent: false,
        })
    }

    pub fn write_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Local(w) => w.write_output(data),
            Self::Remote {
                tx,
                start,
                meta,
                header_sent,
            } => {
                let mut batch = String::new();
                if !*header_sent {
                    let ts = jiff::Timestamp::now().as_second();
                    batch.push_str(&asciinema_header_line(meta, ts));
                    batch.push('\n');
                    *header_sent = true;
                }
                let text = String::from_utf8_lossy(data);
                let t = start.elapsed().as_secs_f64();
                batch.push_str(&asciinema_output_event(t, &text));
                batch.push('\n');
                if tx.try_send(batch.into_bytes()).is_err() {
                    anyhow::bail!("recording channel full or closed");
                }
                Ok(())
            }
        }
    }

    /// Finalize the recording. Returns `(meta, cast)` for local recordings so
    /// the caller can index/upload; remote recordings finalize on the recorder.
    pub fn finish(
        self,
        store: Option<&RecordingStore>,
        duration_ms: u64,
    ) -> anyhow::Result<Option<(RecordingMeta, FinalizedCast)>> {
        match self {
            Self::Local(w) => {
                let meta = w.meta.clone();
                let finalized = w.finish()?;
                if let Some(store) = store {
                    store.index_finished(
                        &meta,
                        &finalized.path,
                        finalized.byte_size,
                        &finalized.sha256_hex,
                        duration_ms,
                    )?;
                }
                Ok(Some((meta, finalized)))
            }
            Self::Remote { tx, .. } => {
                drop(tx);
                Ok(None)
            }
        }
    }
}

/// Returns true if the session must abort because recording is required.
pub fn recorder_unavailable(enforce: bool) -> bool {
    enforce
}

#[allow(clippy::too_many_arguments)]
pub fn make_meta(
    session_id: &str,
    peer_endpoint: &str,
    peer_hostname: Option<String>,
    user: &str,
    machine: &str,
    network: &str,
    width: u16,
    height: u16,
    term: &str,
) -> RecordingMeta {
    RecordingMeta {
        session_id: session_id.into(),
        peer_endpoint: peer_endpoint.into(),
        peer_hostname,
        user: user.into(),
        machine: machine.into(),
        network: network.into(),
        width,
        height,
        term: term.into(),
        shell: String::new(),
    }
}
