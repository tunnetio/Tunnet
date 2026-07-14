//! Direct-mode membership via [iroh-docs](https://github.com/n0-computer/iroh-docs).
//!
//! One document per Direct network. Keys:
//! - `meta/name`, `meta/coordinator`, `meta/subnet`, `meta/created_at`
//! - `peers/<endpoint_id>/{hostname,ip,collision_index,tags,status,joined_at,coordinator}`

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use iroh::Endpoint;
use iroh::protocol::ProtocolHandler;
use iroh_blobs::store::fs::FsStore;
use iroh_docs::api::Doc;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::engine::LiveEvent;
use iroh_docs::protocol::Docs;
use iroh_docs::store::Query;
use iroh_docs::{AuthorId, DocTicket, NamespaceId};
use iroh_gossip::net::Gossip;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::acl::AclEngine;
use crate::direct::auth::AuthCache;
use crate::routing::RoutingTable;
use crate::state::{DirectState, StatePaths};

const SUBNET: &str = "100.64.0.0/10";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipEntry {
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: Ipv4Addr,
    #[serde(default)]
    pub collision_index: u8,
    #[serde(default)]
    pub tags: Vec<String>,
    pub joined_at: DateTime<Utc>,
    #[serde(default)]
    pub coordinator: bool,
    #[serde(default = "default_online")]
    pub status: String,
}

fn default_online() -> String {
    "online".into()
}

fn peer_key(endpoint_id: &str, field: &str) -> Bytes {
    Bytes::from(format!("peers/{endpoint_id}/{field}"))
}

fn meta_key(field: &str) -> Bytes {
    Bytes::from(format!("meta/{field}"))
}

fn parse_peer_key(key: &[u8]) -> Option<(String, String)> {
    let s = std::str::from_utf8(key).ok()?;
    let rest = s.strip_prefix("peers/")?;
    let (id, field) = rest.split_once('/')?;
    if id.is_empty() || field.is_empty() || field.contains('/') {
        return None;
    }
    Some((id.to_string(), field.to_string()))
}

/// Live Direct membership document (iroh-docs) plus protocol handlers for accept.
#[derive(Clone)]
pub struct DocsMembership {
    inner: Arc<DocsInner>,
}

struct DocsInner {
    docs: Docs,
    gossip: Gossip,
    blobs: FsStore,
    doc: Doc,
    author: AuthorId,
    members: Mutex<HashMap<String, MembershipEntry>>,
    network_name: String,
    self_endpoint_id: String,
    paths: StatePaths,
}

/// Inputs for [`DocsMembership::bootstrap`].
pub struct DocsBootstrap<'a> {
    pub endpoint: Endpoint,
    pub paths: &'a StatePaths,
    pub direct: &'a DirectState,
    pub self_endpoint_id: &'a str,
    pub self_entry: MembershipEntry,
    pub blobs: FsStore,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub auth: AuthCache,
    pub policy: tuntun_common::policy::PolicyBundle,
}

impl DocsMembership {
    pub fn docs_protocol(&self) -> Docs {
        self.inner.docs.clone()
    }

    pub fn gossip(&self) -> Gossip {
        self.inner.gossip.clone()
    }

    pub fn namespace_id(&self) -> NamespaceId {
        self.inner.doc.id()
    }

    pub fn snapshot_members(&self) -> Vec<MembershipEntry> {
        let mut v: Vec<_> = self.inner.members.lock().values().cloned().collect();
        v.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        v
    }

    pub async fn share_write_ticket(&self) -> anyhow::Result<String> {
        let ticket = self
            .inner
            .doc
            .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
            .await
            .context("share write ticket")?;
        Ok(ticket.to_string())
    }

    /// Bootstrap docs for a Direct network (create or import).
    ///
    /// `blobs` must be the same store served on `iroh_blobs::ALPN`.
    pub async fn bootstrap(
        cfg: DocsBootstrap<'_>,
    ) -> anyhow::Result<(Self, Option<String>, Option<String>)> {
        let DocsBootstrap {
            endpoint,
            paths,
            direct,
            self_endpoint_id,
            self_entry,
            blobs,
            routes,
            acl,
            auth,
            policy,
        } = cfg;
        paths.ensure()?;
        let docs_dir = paths.dir.join("docs");
        std::fs::create_dir_all(&docs_dir)?;

        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(docs_dir)
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await
            .context("spawn Docs")?;

        let author = docs.author_default().await.context("default author")?;

        let (doc, created_ticket, namespace_str) = if let Some(ticket_str) = &direct.doc_ticket {
            let ticket = DocTicket::from_str(ticket_str).context("parse doc_ticket")?;
            let (doc, _events) = docs
                .import_and_subscribe(ticket)
                .await
                .context("import doc ticket")?;
            let ns = doc.id().to_string();
            (doc, None, Some(ns))
        } else if let Some(ns) = &direct.namespace_id {
            let id = NamespaceId::from_str(ns).context("parse namespace_id")?;
            let doc = docs
                .open(id)
                .await
                .context("open namespace")?
                .context("namespace not found locally; re-join or recreate")?;
            (doc, None, Some(ns.clone()))
        } else if direct.coordinator {
            let doc = docs.create().await.context("create membership doc")?;
            let ticket = doc
                .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
                .await
                .context("share new doc")?;
            let ns = doc.id().to_string();
            seed_meta(&doc, author, direct, self_endpoint_id).await?;
            (doc, Some(ticket.to_string()), Some(ns))
        } else {
            anyhow::bail!(
                "Direct join state is missing doc_ticket; re-run `tuntun join` with a fresh invite"
            );
        };

        let events = doc.subscribe().await.context("subscribe doc")?;

        let membership = Self {
            inner: Arc::new(DocsInner {
                docs,
                gossip,
                blobs,
                doc: doc.clone(),
                author,
                members: Mutex::new(HashMap::new()),
                network_name: direct.network_name.clone(),
                self_endpoint_id: self_endpoint_id.to_string(),
                paths: paths.clone_paths(),
            }),
        };

        membership
            .write_peer_entry(&self_entry)
            .await
            .context("write self peer entry")?;

        membership.rebuild_from_doc().await?;
        membership.apply_to_routes(&routes, &acl, &auth, &policy);
        if let Err(e) = membership.apply_pending_kicks().await {
            tracing::warn!(?e, "apply pending kicks");
        }

        let bg = membership.clone();
        let routes_bg = routes.clone();
        let acl_bg = acl.clone();
        let auth_bg = auth.clone();
        let policy_bg = policy.clone();
        tokio::spawn(async move {
            let mut kick_tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tokio::pin!(events);
            loop {
                tokio::select! {
                    ev = events.next() => {
                        match ev {
                            Some(Ok(LiveEvent::InsertLocal { .. }))
                            | Some(Ok(LiveEvent::InsertRemote { .. }))
                            | Some(Ok(LiveEvent::ContentReady { .. }))
                            | Some(Ok(LiveEvent::PendingContentReady))
                            | Some(Ok(LiveEvent::SyncFinished(_))) => {
                                if let Err(e) = bg.rebuild_from_doc().await {
                                    tracing::debug!(?e, "docs membership rebuild");
                                    continue;
                                }
                                bg.apply_to_routes(&routes_bg, &acl_bg, &auth_bg, &policy_bg);
                            }
                            Some(Ok(LiveEvent::NeighborUp(pk))) => {
                                tracing::debug!(peer = %pk, "docs neighbor up");
                            }
                            Some(Ok(LiveEvent::NeighborDown(pk))) => {
                                tracing::debug!(peer = %pk, "docs neighbor down");
                            }
                            Some(Err(e)) => {
                                tracing::warn!(?e, "docs live event error");
                                break;
                            }
                            None => break,
                        }
                    }
                    _ = kick_tick.tick() => {
                        let _ = bg.apply_pending_kicks().await;
                    }
                }
            }
        });

        Ok((membership, created_ticket, namespace_str))
    }

    pub async fn write_peer_entry(&self, entry: &MembershipEntry) -> anyhow::Result<()> {
        let author = self.inner.author;
        let doc = &self.inner.doc;
        let id = &entry.endpoint_id;
        set_str(doc, author, peer_key(id, "hostname"), &entry.hostname).await?;
        set_str(doc, author, peer_key(id, "ip"), &entry.ipv4.to_string()).await?;
        set_str(
            doc,
            author,
            peer_key(id, "collision_index"),
            &entry.collision_index.to_string(),
        )
        .await?;
        set_str(
            doc,
            author,
            peer_key(id, "tags"),
            &serde_json::to_string(&entry.tags)?,
        )
        .await?;
        set_str(doc, author, peer_key(id, "status"), &entry.status).await?;
        set_str(
            doc,
            author,
            peer_key(id, "joined_at"),
            &entry.joined_at.to_rfc3339(),
        )
        .await?;
        set_str(
            doc,
            author,
            peer_key(id, "coordinator"),
            if entry.coordinator { "true" } else { "false" },
        )
        .await?;
        set_str(
            doc,
            author,
            peer_key(id, "last_seen"),
            &Utc::now().to_rfc3339(),
        )
        .await?;
        Ok(())
    }

    /// Coordinator marks a peer as kicked (wins via latest timestamp on status key).
    pub async fn kick_peer(&self, endpoint_id: &str) -> anyhow::Result<()> {
        set_str(
            &self.inner.doc,
            self.inner.author,
            peer_key(endpoint_id, "status"),
            "kicked",
        )
        .await?;
        self.inner.members.lock().remove(endpoint_id);
        Ok(())
    }

    pub async fn rebuild_from_doc(&self) -> anyhow::Result<()> {
        let stream = self
            .inner
            .doc
            .get_many(Query::single_latest_per_key().key_prefix("peers/"))
            .await
            .context("get_many peers")?;
        tokio::pin!(stream);

        let mut fields: HashMap<String, HashMap<String, String>> = HashMap::new();
        while let Some(item) = stream.next().await {
            let entry = item.context("peer entry")?;
            let Some((id, field)) = parse_peer_key(entry.key()) else {
                continue;
            };
            let hash = entry.content_hash();
            let bytes = self
                .inner
                .blobs
                .get_bytes(hash)
                .await
                .map_err(|e| anyhow::anyhow!("get blob for {id}/{field}: {e}"))?;
            let value = String::from_utf8_lossy(&bytes).into_owned();
            fields.entry(id).or_default().insert(field, value);
        }

        let mut map = HashMap::new();
        for (endpoint_id, f) in fields {
            let status = f.get("status").cloned().unwrap_or_else(|| "online".into());
            if status == "kicked" {
                continue;
            }
            let hostname = f.get("hostname").cloned().unwrap_or_else(|| "peer".into());
            let ipv4 = f
                .get("ip")
                .and_then(|s| s.parse().ok())
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            if ipv4.is_unspecified() {
                continue;
            }
            let collision_index = f
                .get("collision_index")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let tags = f
                .get("tags")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let joined_at = f
                .get("joined_at")
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            let coordinator = f.get("coordinator").map(|s| s == "true").unwrap_or(false);
            map.insert(
                endpoint_id.clone(),
                MembershipEntry {
                    endpoint_id,
                    hostname,
                    ipv4,
                    collision_index,
                    tags,
                    joined_at,
                    coordinator,
                    status,
                },
            );
        }
        *self.inner.members.lock() = map;
        Ok(())
    }

    pub fn apply_to_routes(
        &self,
        routes: &RoutingTable,
        acl: &AclEngine,
        auth: &AuthCache,
        policy: &tuntun_common::policy::PolicyBundle,
    ) {
        let members = self.snapshot_members();
        let peers: Vec<tuntun_common::PeerEntry> = members
            .iter()
            .filter(|m| m.endpoint_id != self.inner.self_endpoint_id)
            .filter(|m| m.status != "kicked")
            .map(|m| tuntun_common::PeerEntry {
                ip: m.ipv4,
                endpoint_id: m.endpoint_id.clone(),
                hostname: m.hostname.clone(),
                tags: m.tags.clone(),
            })
            .collect();
        let version = members.len() as u64;
        routes.replace(
            &peers,
            &[],
            &[],
            &[],
            &tuntun_common::DeviceProfile::default(),
            &tuntun_common::DnsConfig::default(),
            &self.inner.network_name,
            &self.inner.self_endpoint_id,
            version,
        );
        acl.replace_bundle(policy.clone());
        for m in &members {
            if m.status != "kicked" {
                auth.insert(m.endpoint_id.clone());
            }
        }
        // Cache for offline CLI (upgrade, etc.).
        if let Ok(json) = serde_json::to_vec_pretty(&members) {
            let _ = std::fs::write(self.inner.paths.dir.join("direct_members_cache.json"), json);
        }
    }

    /// Drain pending kick file written by CLI.
    pub async fn apply_pending_kicks(&self) -> anyhow::Result<()> {
        let kick_path = self.inner.paths.dir.join("direct_pending_kick.json");
        if !kick_path.exists() {
            return Ok(());
        }
        let kicks: Vec<String> = serde_json::from_slice(&std::fs::read(&kick_path)?)?;
        for id in &kicks {
            self.kick_peer(id).await?;
        }
        let _ = std::fs::remove_file(&kick_path);
        Ok(())
    }

    /// Accept inbound docs / gossip ALPNs.
    pub async fn accept_docs(&self, conn: iroh::endpoint::Connection) {
        if let Err(e) = self.inner.docs.accept(conn).await {
            tracing::debug!(?e, "docs accept ended");
        }
    }

    pub async fn accept_gossip(&self, conn: iroh::endpoint::Connection) {
        if let Err(e) = self.inner.gossip.handle_connection(conn).await {
            tracing::debug!(?e, "gossip accept ended");
        }
    }

    pub fn blobs_store_path(paths: &StatePaths) -> PathBuf {
        paths.dir.join("blobs")
    }
}

async fn seed_meta(
    doc: &Doc,
    author: AuthorId,
    direct: &DirectState,
    coordinator_id: &str,
) -> anyhow::Result<()> {
    set_str(doc, author, meta_key("name"), &direct.network_name).await?;
    set_str(doc, author, meta_key("coordinator"), coordinator_id).await?;
    set_str(doc, author, meta_key("subnet"), SUBNET).await?;
    set_str(
        doc,
        author,
        meta_key("created_at"),
        &direct.created_at.to_rfc3339(),
    )
    .await?;
    Ok(())
}

async fn set_str(doc: &Doc, author: AuthorId, key: Bytes, value: &str) -> anyhow::Result<()> {
    doc.set_bytes(author, key, Bytes::copy_from_slice(value.as_bytes()))
        .await
        .context("doc set_bytes")?;
    Ok(())
}

/// Approved peer ids waiting for a re-join to receive a write ticket.
pub fn load_approved(paths: &StatePaths) -> anyhow::Result<Vec<String>> {
    let p = paths.dir.join("direct_approved.json");
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&std::fs::read(p)?)?)
}

pub fn save_approved(paths: &StatePaths, ids: &[String]) -> anyhow::Result<()> {
    paths.ensure()?;
    std::fs::write(
        paths.dir.join("direct_approved.json"),
        serde_json::to_vec_pretty(ids)?,
    )?;
    Ok(())
}
