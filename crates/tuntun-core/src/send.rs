//! P2P file transfer via iroh-blobs + TunTun offer ALPN.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::ProtocolHandler;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobFormat, BlobsProtocol, Hash, HashAndFormat};
use parking_lot::Mutex;
use std::str::FromStr;
use tokio::sync::mpsc;
use tuntun_common::send::{
    ConsentDecision, SEND_ALPN, SendBlobFormat, SendConsentMode, SendWireMsg, TransferDecision,
    TransferDone, TransferOffer,
};
use tuntun_common::ws::ClientMsg;
use uuid::Uuid;

use crate::acl::AclEngine;
use crate::iroh_pool::ConnPool;
use crate::routing::RoutingTable;

const SENDER_TTL: Duration = Duration::from_secs(60 * 60);
const PROGRESS_THROTTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Offered,
    Pending,
    Transferring,
    Completed,
    Failed,
    Rejected,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Pending => "pending",
            Self::Transferring => "transferring",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransferRecord {
    pub transfer_id: String,
    pub direction: TransferDirection,
    pub peer_endpoint_id: String,
    pub peer_hostname: Option<String>,
    pub file_name: String,
    pub size: u64,
    pub hash: String,
    pub format: SendBlobFormat,
    pub is_directory: bool,
    pub status: TransferStatus,
    pub percent: f32,
    pub bytes_transferred: u64,
    pub message: Option<String>,
    pub error: Option<String>,
    pub inbox_path: Option<String>,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone)]
pub struct SendConfig {
    pub consent: SendConsentMode,
    pub inbox_path: PathBuf,
    pub pin_blobs: bool,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            consent: SendConsentMode::Prompt,
            inbox_path: default_inbox_path(),
            pin_blobs: false,
        }
    }
}

fn default_inbox_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        return PathBuf::from(home).join("TunTun").join("inbox");
    }
    PathBuf::from("./TunTun/inbox")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct SendManager {
    inner: Arc<SendInner>,
}

struct SendInner {
    store: FsStore,
    blobs: BlobsProtocol,
    pool: ConnPool,
    routes: RoutingTable,
    acl: AclEngine,
    self_endpoint_id: String,
    config: Mutex<SendConfig>,
    transfers: Mutex<HashMap<String, TransferRecord>>,
    /// Outbound sender tags kept until TTL after completion.
    retained_tags: Mutex<Vec<(String, Instant)>>,
    /// Pending inbound offers waiting for prompt consent.
    pending: Mutex<HashMap<String, PendingOffer>>,
    client_tx: Mutex<Option<mpsc::Sender<ClientMsg>>>,
}

struct PendingOffer {
    offer: TransferOffer,
    peer: EndpointId,
    send: SendStream,
    recv: RecvStream,
}

impl SendManager {
    pub async fn open(
        blobs_dir: PathBuf,
        pool: ConnPool,
        routes: RoutingTable,
        acl: AclEngine,
        self_endpoint_id: String,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&blobs_dir)
            .with_context(|| format!("mkdir blobs {}", blobs_dir.display()))?;
        let store = FsStore::load(&blobs_dir)
            .await
            .map_err(|e| anyhow::anyhow!("open FsStore: {e}"))?;
        Self::from_store(store, pool, routes, acl, self_endpoint_id).await
    }

    pub async fn from_store(
        store: FsStore,
        pool: ConnPool,
        routes: RoutingTable,
        acl: AclEngine,
        self_endpoint_id: String,
    ) -> anyhow::Result<Self> {
        let blobs = BlobsProtocol::new(store.as_ref(), None);
        let mgr = Self {
            inner: Arc::new(SendInner {
                store,
                blobs,
                pool,
                routes,
                acl,
                self_endpoint_id,
                config: Mutex::new(SendConfig::default()),
                transfers: Mutex::new(HashMap::new()),
                retained_tags: Mutex::new(Vec::new()),
                pending: Mutex::new(HashMap::new()),
                client_tx: Mutex::new(None),
            }),
        };
        let cfg = mgr.config();
        std::fs::create_dir_all(&cfg.inbox_path).ok();
        let weak = mgr.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                weak.gc_retained_tags().await;
            }
        });
        Ok(mgr)
    }

    pub fn set_client_tx(&self, tx: mpsc::Sender<ClientMsg>) {
        *self.inner.client_tx.lock() = Some(tx);
    }

    pub fn blobs_protocol(&self) -> BlobsProtocol {
        self.inner.blobs.clone()
    }

    pub fn config(&self) -> SendConfig {
        self.inner.config.lock().clone()
    }

    pub fn set_config(&self, cfg: SendConfig) {
        std::fs::create_dir_all(&cfg.inbox_path).ok();
        *self.inner.config.lock() = cfg;
    }

    pub fn list_active(&self) -> Vec<TransferRecord> {
        self.inner
            .transfers
            .lock()
            .values()
            .filter(|t| {
                matches!(
                    t.status,
                    TransferStatus::Offered
                        | TransferStatus::Pending
                        | TransferStatus::Transferring
                )
            })
            .cloned()
            .collect()
    }

    pub fn list_history(&self) -> Vec<TransferRecord> {
        let mut v: Vec<_> = self
            .inner
            .transfers
            .lock()
            .values()
            .filter(|t| {
                matches!(
                    t.status,
                    TransferStatus::Completed | TransferStatus::Failed | TransferStatus::Rejected
                )
            })
            .cloned()
            .collect();
        v.sort_by_key(|t| std::cmp::Reverse(t.started_at_ms));
        v
    }

    pub fn list_pending(&self) -> Vec<TransferRecord> {
        self.inner
            .transfers
            .lock()
            .values()
            .filter(|t| t.status == TransferStatus::Pending)
            .cloned()
            .collect()
    }

    async fn emit(&self, msg: ClientMsg) {
        let tx = self.inner.client_tx.lock().clone();
        if let Some(tx) = tx {
            let _ = tx.send(msg).await;
        }
    }

    fn upsert(&self, record: TransferRecord) {
        self.inner
            .transfers
            .lock()
            .insert(record.transfer_id.clone(), record);
    }

    fn update_status(
        &self,
        id: &str,
        status: TransferStatus,
        error: Option<String>,
        inbox: Option<String>,
    ) {
        let mut guard = self.inner.transfers.lock();
        if let Some(t) = guard.get_mut(id) {
            t.status = status;
            t.error = error;
            if inbox.is_some() {
                t.inbox_path = inbox;
            }
            if matches!(
                status,
                TransferStatus::Completed | TransferStatus::Failed | TransferStatus::Rejected
            ) {
                t.completed_at_ms = Some(now_ms());
                if status == TransferStatus::Completed {
                    t.percent = 100.0;
                }
            }
        }
    }

    fn update_progress(&self, id: &str, bytes: u64, total: u64) {
        let mut guard = self.inner.transfers.lock();
        if let Some(t) = guard.get_mut(id) {
            t.bytes_transferred = bytes;
            t.status = TransferStatus::Transferring;
            if total > 0 {
                t.percent = (bytes as f32 / total as f32) * 100.0;
            }
        }
    }

    /// Resolve target hostname / IP / endpoint id / `tag:foo` to peer endpoint ids.
    pub fn resolve_targets(
        &self,
        target: &str,
    ) -> anyhow::Result<Vec<Arc<crate::routing::PeerInfo>>> {
        if let Some(tag) = target.strip_prefix("tag:") {
            let tag = tag.trim();
            if tag.is_empty() {
                bail!("empty tag");
            }
            let peers: Vec<_> = self
                .inner
                .routes
                .peers()
                .into_iter()
                .filter(|p| p.tags.iter().any(|t| t == tag))
                .collect();
            if peers.is_empty() {
                bail!("no peers with tag `{tag}`");
            }
            return Ok(peers);
        }
        let peer = if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
            self.inner.routes.lookup_ip(&ip)
        } else {
            self.inner
                .routes
                .lookup_hostname(target)
                .or_else(|| self.inner.routes.lookup_endpoint(target))
        }
        .with_context(|| format!("peer not found: {target}"))?;
        Ok(vec![peer])
    }

    /// Import path, offer to target(s), serve via blobs ALPN.
    ///
    /// When `transfer_id` is `Some`, it is used for the first (or only) peer so
    /// control-plane / dashboard IDs stay aligned. Extra multicast peers get new UUIDs.
    pub async fn send_file(
        &self,
        path: &Path,
        target: &str,
        message: Option<String>,
    ) -> anyhow::Result<Vec<TransferRecord>> {
        self.send_file_with_id(path, target, message, None).await
    }

    pub async fn send_file_with_id(
        &self,
        path: &Path,
        target: &str,
        message: Option<String>,
        transfer_id: Option<String>,
    ) -> anyhow::Result<Vec<TransferRecord>> {
        let peers = self.resolve_targets(target)?;
        let imported = self.import_path(path).await?;
        let mut records = Vec::new();
        for (i, peer) in peers.into_iter().enumerate() {
            let transfer_id = if i == 0 {
                transfer_id
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string())
            } else {
                Uuid::new_v4().to_string()
            };
            let record = TransferRecord {
                transfer_id: transfer_id.clone(),
                direction: TransferDirection::Outbound,
                peer_endpoint_id: peer.endpoint_hex.clone(),
                peer_hostname: Some(peer.hostname.clone()),
                file_name: imported.file_name.clone(),
                size: imported.size,
                hash: imported.hash.to_hex(),
                format: imported.format,
                is_directory: imported.is_directory,
                status: TransferStatus::Offered,
                percent: 0.0,
                bytes_transferred: 0,
                message: message.clone(),
                error: None,
                inbox_path: None,
                started_at_ms: now_ms(),
                completed_at_ms: None,
            };
            self.upsert(record.clone());
            self.emit(ClientMsg::TransferOffer {
                transfer_id: transfer_id.clone(),
                sender_endpoint_id: self.inner.self_endpoint_id.clone(),
                receiver_endpoint_id: Some(peer.endpoint_hex.clone()),
                file_name: imported.file_name.clone(),
                size: imported.size,
                blake3_hash: imported.hash.to_hex(),
                status: "offered".into(),
                message: message.clone(),
            })
            .await;

            let mgr = self.clone();
            let peer_id: EndpointId = peer
                .endpoint_hex
                .parse()
                .context("parse peer endpoint id")?;
            let offer = TransferOffer {
                transfer_id: transfer_id.clone(),
                hash: imported.hash.to_hex(),
                format: imported.format,
                file_name: imported.file_name.clone(),
                size: imported.size,
                sender_endpoint_id: self.inner.self_endpoint_id.clone(),
                message: message.clone(),
                is_directory: imported.is_directory,
            };
            let tag_name = transfer_id.clone();
            let tid = transfer_id.clone();
            let hash = imported.hash;
            let format = imported.format;
            tokio::spawn(async move {
                if let Err(e) = mgr
                    .run_outbound(peer_id, offer, tag_name, hash, format)
                    .await
                {
                    tracing::warn!(?e, "outbound transfer failed");
                    mgr.update_status(&tid, TransferStatus::Failed, Some(e.to_string()), None);
                    mgr.emit(ClientMsg::TransferFailed {
                        transfer_id: tid,
                        error: e.to_string(),
                        rejected: false,
                    })
                    .await;
                }
            });
            records.push(record);
        }
        Ok(records)
    }

    async fn run_outbound(
        &self,
        peer: EndpointId,
        offer: TransferOffer,
        tag_name: String,
        hash: Hash,
        format: SendBlobFormat,
    ) -> anyhow::Result<()> {
        let transfer_id = offer.transfer_id.clone();
        // Persist a named tag so the blob survives until TTL.
        let haf = HashAndFormat {
            hash,
            format: match format {
                SendBlobFormat::Blob => BlobFormat::Raw,
                SendBlobFormat::HashSeq => BlobFormat::HashSeq,
            },
        };
        self.inner
            .store
            .tags()
            .set(tag_name.as_bytes(), haf)
            .await
            .map_err(|e| anyhow::anyhow!("set tag: {e}"))?;

        let conn = self.inner.pool.get_alpn(peer, SEND_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.context("open_bi send")?;
        write_wire(&mut send, &SendWireMsg::Offer(offer)).await?;
        let decision = match read_wire(&mut recv).await? {
            SendWireMsg::Decision(d) => d,
            other => bail!("expected Decision, got {other:?}"),
        };
        if !decision.accepted {
            self.update_status(
                &transfer_id,
                TransferStatus::Rejected,
                decision.reason.clone(),
                None,
            );
            let _ = self.inner.store.tags().delete(tag_name.as_bytes()).await;
            self.emit(ClientMsg::TransferFailed {
                transfer_id: transfer_id.clone(),
                error: decision.reason.unwrap_or_else(|| "rejected".into()),
                rejected: true,
            })
            .await;
            return Ok(());
        }

        self.update_status(&transfer_id, TransferStatus::Transferring, None, None);
        // Wait for Done from receiver.
        match read_wire(&mut recv).await {
            Ok(SendWireMsg::Done(done)) => {
                if done.status == "completed" {
                    self.update_status(
                        &transfer_id,
                        TransferStatus::Completed,
                        None,
                        done.inbox_path,
                    );
                    self.inner
                        .retained_tags
                        .lock()
                        .push((tag_name, Instant::now() + SENDER_TTL));
                    self.emit(ClientMsg::TransferComplete {
                        transfer_id,
                        inbox_path: None,
                        duration_ms: None,
                    })
                    .await;
                } else {
                    self.update_status(
                        &transfer_id,
                        TransferStatus::Failed,
                        done.error.clone(),
                        None,
                    );
                    let _ = self.inner.store.tags().delete(tag_name.as_bytes()).await;
                    self.emit(ClientMsg::TransferFailed {
                        transfer_id,
                        error: done.error.unwrap_or_else(|| "failed".into()),
                        rejected: false,
                    })
                    .await;
                }
            }
            Ok(other) => bail!("expected Done, got {other:?}"),
            Err(e) => {
                self.update_status(
                    &transfer_id,
                    TransferStatus::Failed,
                    Some(e.to_string()),
                    None,
                );
                self.emit(ClientMsg::TransferFailed {
                    transfer_id,
                    error: e.to_string(),
                    rejected: false,
                })
                .await;
            }
        }
        Ok(())
    }

    /// Handle inbound SEND_ALPN connection (offer stream).
    pub async fn handle_offer_connection(&self, conn: Connection) {
        let peer_hex = format!("{}", conn.remote_id());
        if !self.inner.acl.allow_inbound_peer(&peer_hex) {
            tracing::warn!(%peer_hex, "send offer blocked by ACL");
            return;
        }
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(?e, "send accept_bi closed");
                return;
            }
        };
        let offer = match read_wire(&mut recv).await {
            Ok(SendWireMsg::Offer(o)) => o,
            Ok(other) => {
                tracing::warn!(?other, "unexpected first send msg");
                return;
            }
            Err(e) => {
                tracing::warn!(?e, "read offer failed");
                return;
            }
        };

        let peer: EndpointId = match peer_hex.parse() {
            Ok(p) => p,
            Err(_) => return,
        };
        let hostname = self
            .inner
            .routes
            .lookup_endpoint(&peer_hex)
            .map(|p| p.hostname.clone());

        let record = TransferRecord {
            transfer_id: offer.transfer_id.clone(),
            direction: TransferDirection::Inbound,
            peer_endpoint_id: peer_hex.clone(),
            peer_hostname: hostname,
            file_name: offer.file_name.clone(),
            size: offer.size,
            hash: offer.hash.clone(),
            format: offer.format,
            is_directory: offer.is_directory,
            status: TransferStatus::Pending,
            percent: 0.0,
            bytes_transferred: 0,
            message: offer.message.clone(),
            error: None,
            inbox_path: None,
            started_at_ms: now_ms(),
            completed_at_ms: None,
        };
        self.upsert(record);
        self.emit(ClientMsg::TransferOffer {
            transfer_id: offer.transfer_id.clone(),
            sender_endpoint_id: offer.sender_endpoint_id.clone(),
            receiver_endpoint_id: Some(self.inner.self_endpoint_id.clone()),
            file_name: offer.file_name.clone(),
            size: offer.size,
            blake3_hash: offer.hash.clone(),
            status: "pending".into(),
            message: offer.message.clone(),
        })
        .await;

        let consent = self.decide_consent(&peer_hex);
        match consent {
            ConsentDecision::Accept => {
                if let Err(e) = self.accept_offer_inner(offer, peer, send, recv).await {
                    tracing::warn!(?e, "accept offer failed");
                }
            }
            ConsentDecision::Deny => {
                let id = offer.transfer_id.clone();
                let _ = write_wire(
                    &mut send,
                    &SendWireMsg::Decision(TransferDecision {
                        transfer_id: id.clone(),
                        accepted: false,
                        reason: Some("denied by consent policy".into()),
                    }),
                )
                .await;
                self.update_status(&id, TransferStatus::Rejected, Some("denied".into()), None);
                self.emit(ClientMsg::TransferFailed {
                    transfer_id: id,
                    error: "denied by consent policy".into(),
                    rejected: true,
                })
                .await;
            }
            ConsentDecision::Prompt => {
                self.inner.pending.lock().insert(
                    offer.transfer_id.clone(),
                    PendingOffer {
                        offer,
                        peer,
                        send,
                        recv,
                    },
                );
            }
        }
    }

    fn decide_consent(&self, peer_hex: &str) -> ConsentDecision {
        let mode = self.inner.config.lock().consent;
        mode.decide(self.peer_shares_tag(peer_hex))
    }

    /// True when this machine and the peer share at least one mesh tag.
    pub fn peer_shares_tag(&self, peer_hex: &str) -> bool {
        let self_tags = self.inner.acl.self_id.load().tags.clone();
        if self_tags.is_empty() {
            return false;
        }
        let Some(peer) = self.inner.routes.lookup_endpoint(peer_hex) else {
            return false;
        };
        peer.tags.iter().any(|t| self_tags.contains(t))
    }

    pub async fn accept_pending(&self, transfer_id: &str) -> anyhow::Result<TransferRecord> {
        let pending = self
            .inner
            .pending
            .lock()
            .remove(transfer_id)
            .with_context(|| format!("no pending transfer `{transfer_id}`"))?;
        self.accept_offer_inner(pending.offer, pending.peer, pending.send, pending.recv)
            .await?;
        self.inner
            .transfers
            .lock()
            .get(transfer_id)
            .cloned()
            .context("transfer missing after accept")
    }

    pub async fn reject_pending(
        &self,
        transfer_id: &str,
        reason: Option<String>,
    ) -> anyhow::Result<()> {
        let mut pending = self
            .inner
            .pending
            .lock()
            .remove(transfer_id)
            .with_context(|| format!("no pending transfer `{transfer_id}`"))?;
        let reason = reason.unwrap_or_else(|| "rejected".into());
        write_wire(
            &mut pending.send,
            &SendWireMsg::Decision(TransferDecision {
                transfer_id: transfer_id.to_string(),
                accepted: false,
                reason: Some(reason.clone()),
            }),
        )
        .await?;
        self.update_status(
            transfer_id,
            TransferStatus::Rejected,
            Some(reason.clone()),
            None,
        );
        self.emit(ClientMsg::TransferFailed {
            transfer_id: transfer_id.to_string(),
            error: reason,
            rejected: true,
        })
        .await;
        Ok(())
    }

    async fn accept_offer_inner(
        &self,
        offer: TransferOffer,
        peer: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> anyhow::Result<()> {
        let transfer_id = offer.transfer_id.clone();
        write_wire(
            &mut send,
            &SendWireMsg::Decision(TransferDecision {
                transfer_id: transfer_id.clone(),
                accepted: true,
                reason: None,
            }),
        )
        .await?;

        self.update_status(&transfer_id, TransferStatus::Transferring, None, None);
        let hash = Hash::from_str(&offer.hash).map_err(|e| anyhow::anyhow!("invalid hash: {e}"))?;
        let format = match offer.format {
            SendBlobFormat::Blob => BlobFormat::Raw,
            SendBlobFormat::HashSeq => BlobFormat::HashSeq,
        };

        let started = Instant::now();
        let result = self
            .download_from_peer(peer, hash, format, offer.size, &transfer_id)
            .await;

        match result {
            Ok(()) => {
                let pin = self.inner.config.lock().pin_blobs;
                if pin {
                    let haf = HashAndFormat { hash, format };
                    let tag = format!("pin-{transfer_id}");
                    let _ = self.inner.store.tags().set(tag.as_bytes(), haf).await;
                }
                let inbox = self
                    .export_to_inbox(&offer, hash)
                    .await
                    .context("export to inbox")?;
                let inbox_str = inbox.display().to_string();
                // When not pinning, drop any named tags so FsStore GC can reclaim
                // after TempTags from the download are released.
                if !pin {
                    let _ = self
                        .inner
                        .store
                        .tags()
                        .delete(format!("recv-{transfer_id}").as_bytes())
                        .await;
                    let _ = self.inner.store.tags().delete(transfer_id.as_bytes()).await;
                }
                self.update_status(
                    &transfer_id,
                    TransferStatus::Completed,
                    None,
                    Some(inbox_str.clone()),
                );
                let _ = write_wire(
                    &mut send,
                    &SendWireMsg::Done(TransferDone {
                        transfer_id: transfer_id.clone(),
                        status: "completed".into(),
                        error: None,
                        inbox_path: Some(inbox_str.clone()),
                    }),
                )
                .await;
                // Keep recv half alive briefly
                let _ = &mut recv;
                self.emit(ClientMsg::TransferComplete {
                    transfer_id,
                    inbox_path: Some(inbox_str),
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                })
                .await;
            }
            Err(e) => {
                self.update_status(
                    &transfer_id,
                    TransferStatus::Failed,
                    Some(e.to_string()),
                    None,
                );
                let _ = write_wire(
                    &mut send,
                    &SendWireMsg::Done(TransferDone {
                        transfer_id: transfer_id.clone(),
                        status: "failed".into(),
                        error: Some(e.to_string()),
                        inbox_path: None,
                    }),
                )
                .await;
                self.emit(ClientMsg::TransferFailed {
                    transfer_id,
                    error: e.to_string(),
                    rejected: false,
                })
                .await;
                return Err(e);
            }
        }
        Ok(())
    }

    async fn download_from_peer(
        &self,
        peer: EndpointId,
        hash: Hash,
        format: BlobFormat,
        total: u64,
        transfer_id: &str,
    ) -> anyhow::Result<()> {
        let conn = self
            .inner
            .pool
            .get_alpn(peer, iroh_blobs::ALPN)
            .await
            .context("connect blobs ALPN")?;
        let progress = self
            .inner
            .store
            .remote()
            .fetch(conn, HashAndFormat { hash, format });

        let mut stream = progress.stream();
        use futures_util::StreamExt;
        let mut last_emit = Instant::now() - PROGRESS_THROTTLE;
        let mut last_pct = -1.0f32;
        while let Some(item) = stream.next().await {
            match item {
                iroh_blobs::api::remote::GetProgressItem::Progress(bytes) => {
                    self.update_progress(transfer_id, bytes, total);
                    let pct = if total > 0 {
                        (bytes as f32 / total as f32) * 100.0
                    } else {
                        0.0
                    };
                    if last_emit.elapsed() >= PROGRESS_THROTTLE || (pct - last_pct).abs() >= 1.0 {
                        last_emit = Instant::now();
                        last_pct = pct;
                        self.emit(ClientMsg::TransferProgress {
                            transfer_id: transfer_id.to_string(),
                            percent: pct,
                            bytes_transferred: bytes,
                            bytes_total: Some(total),
                        })
                        .await;
                    }
                }
                iroh_blobs::api::remote::GetProgressItem::Done(_) => return Ok(()),
                iroh_blobs::api::remote::GetProgressItem::Error(e) => {
                    bail!("download failed: {e}");
                }
            }
        }
        bail!("download stream ended without result");
    }

    async fn export_to_inbox(&self, offer: &TransferOffer, hash: Hash) -> anyhow::Result<PathBuf> {
        let inbox = self.inner.config.lock().inbox_path.clone();
        std::fs::create_dir_all(&inbox)?;
        let safe_name = sanitize_file_name(&offer.file_name);
        if offer.is_directory || offer.format == SendBlobFormat::HashSeq {
            let dest_dir = unique_path(inbox.join(&safe_name));
            std::fs::create_dir_all(&dest_dir)?;
            let collection = Collection::load(hash, self.inner.store.as_ref())
                .await
                .map_err(|e| anyhow::anyhow!("load collection: {e}"))?;
            for (name, file_hash) in collection.iter() {
                let target = dest_dir.join(name);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                self.inner
                    .store
                    .export(*file_hash, &target)
                    .await
                    .map_err(|e| anyhow::anyhow!("export {name}: {e}"))?;
            }
            Ok(dest_dir)
        } else {
            let target = unique_path(inbox.join(&safe_name));
            self.inner
                .store
                .export(hash, &target)
                .await
                .map_err(|e| anyhow::anyhow!("export: {e}"))?;
            Ok(target)
        }
    }

    async fn import_path(&self, path: &Path) -> anyhow::Result<ImportedBlob> {
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());

        if meta.is_dir() {
            let mut collection = Collection::default();
            let mut total_size = 0u64;
            collect_dir(
                path,
                path,
                &self.inner.store,
                &mut collection,
                &mut total_size,
            )
            .await?;
            let tag = collection
                .store(self.inner.store.as_ref())
                .await
                .map_err(|e| anyhow::anyhow!("store collection: {e}"))?;
            Ok(ImportedBlob {
                hash: tag.hash(),
                format: SendBlobFormat::HashSeq,
                file_name,
                size: total_size,
                is_directory: true,
            })
        } else {
            let tag = self
                .inner
                .store
                .add_path(path)
                .await
                .map_err(|e| anyhow::anyhow!("add_path: {e}"))?;
            Ok(ImportedBlob {
                hash: tag.hash,
                format: SendBlobFormat::Blob,
                file_name,
                size: meta.len(),
                is_directory: false,
            })
        }
    }

    async fn gc_retained_tags(&self) {
        let now = Instant::now();
        let expired: Vec<String> = {
            let mut guard = self.inner.retained_tags.lock();
            let mut keep = Vec::new();
            let mut expired = Vec::new();
            for (tag, until) in guard.drain(..) {
                if until <= now {
                    expired.push(tag);
                } else {
                    keep.push((tag, until));
                }
            }
            *guard = keep;
            expired
        };
        for tag in expired {
            let _ = self.inner.store.tags().delete(tag.as_bytes()).await;
        }
    }

    /// Serve an inbound blobs ALPN connection.
    pub async fn handle_blobs_connection(&self, conn: Connection) {
        let peer_hex = format!("{}", conn.remote_id());
        if !self.inner.acl.allow_inbound_peer(&peer_hex) {
            tracing::warn!(%peer_hex, "blobs ALPN blocked by ACL");
            conn.close(1u32.into(), b"policy_deny");
            return;
        }
        self.accept_blobs(conn).await;
    }

    /// Blobs accept without ACL (Direct PSK-authed peers / iroh-docs sync).
    pub async fn handle_blobs_connection_trusted(&self, conn: Connection) {
        self.accept_blobs(conn).await;
    }

    async fn accept_blobs(&self, conn: Connection) {
        if let Err(e) = self.inner.blobs.accept(conn).await {
            tracing::debug!(?e, "blobs accept ended");
        }
    }
}

struct ImportedBlob {
    hash: Hash,
    format: SendBlobFormat,
    file_name: String,
    size: u64,
    is_directory: bool,
}

async fn collect_dir(
    root: &Path,
    dir: &Path,
    store: &FsStore,
    collection: &mut Collection,
    total_size: &mut u64,
) -> anyhow::Result<()> {
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();
        let ft = entry.file_type().await?;
        if ft.is_dir() {
            Box::pin(collect_dir(root, &path, store, collection, total_size)).await?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let meta = entry.metadata().await?;
            *total_size += meta.len();
            let tag = store
                .add_path(&path)
                .await
                .map_err(|e| anyhow::anyhow!("add {}: {e}", path.display()))?;
            collection.push(rel, tag.hash); // name is already String
        }
    }
    Ok(())
}

fn sanitize_file_name(name: &str) -> String {
    let name = name.trim().trim_start_matches(['/', '\\']);
    if name.is_empty() || name == "." || name == ".." {
        return "file".into();
    }
    name.replace(['/', '\\', '\0'], "_")
}

fn unique_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let ext = path
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    for i in 1..10_000 {
        let candidate = parent.join(format!("{stem}-{i}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    parent.join(format!("{stem}-{}{ext}", Uuid::new_v4()))
}

async fn write_wire(send: &mut SendStream, msg: &SendWireMsg) -> anyhow::Result<()> {
    let bytes = msg.encode()?;
    let len = u32::try_from(bytes.len()).context("send frame too large")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_wire(recv: &mut RecvStream) -> anyhow::Result<SendWireMsg> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read send frame len")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        bail!("send frame too large ({len})");
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        recv.read_exact(&mut buf)
            .await
            .context("read send frame body")?;
    }
    SendWireMsg::decode(&buf)
}
