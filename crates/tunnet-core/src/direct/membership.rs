//! Direct-mode membership via [iroh-docs](https://github.com/n0-computer/iroh-docs).
//!
//! One document per Direct network. Keys:
//! - `meta/name`, `meta/coordinator`, `meta/subnet`, `meta/created_at`
//! - `peers/<endpoint_id>/{hostname,ip,collision_index,tags,status,joined_at,coordinator,ssh_host_key}`

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
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
use tunnet_common::DnsConfig;
use uuid::Uuid;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
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
    network_id: Uuid,
    join_index: u64,
    network_name: String,
    network_secret: String,
    hostname: String,
    auto_accept_firewall: bool,
    self_endpoint_id: String,
    paths: StatePaths,
    firewall: Option<crate::direct::FirewallEngine>,
    dns: Arc<ArcSwap<DnsConfig>>,
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
    pub policy: tunnet_common::policy::PolicyBundle,
    /// Optional firewall engine for coordinator policy suggestions.
    pub firewall: Option<crate::direct::FirewallEngine>,
    /// PeerDNS config (from tunnet.toml or defaults).
    pub dns: DnsConfig,
    /// Join order among Direct networks (0 = first / outbound winner).
    pub join_index: u64,
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
            firewall,
            dns,
            join_index,
        } = cfg;
        paths.ensure_network_dirs(direct.network_id)?;
        let docs_dir = paths.docs_dir(direct.network_id);

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
                "Direct join state is missing doc_ticket; re-run `tunnet join` with a fresh invite"
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
                network_id: direct.network_id,
                join_index,
                network_name: direct.network_name.clone(),
                network_secret: direct.network_secret.clone(),
                hostname: direct.hostname.clone(),
                auto_accept_firewall: direct.auto_accept_firewall,
                self_endpoint_id: self_endpoint_id.to_string(),
                paths: paths.clone_paths(),
                firewall,
                dns: Arc::new(ArcSwap::from_pointee(dns)),
            }),
        };

        membership
            .write_peer_entry(&self_entry)
            .await
            .context("write self peer entry")?;

        membership.rebuild_from_doc().await?;
        membership.apply_to_routes(&routes, &acl, &auth, &policy);
        if let Err(e) = membership.sync_firewall_policy().await {
            tracing::debug!(?e, "initial firewall policy sync");
        }
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
                                if let Err(e) = bg.sync_firewall_policy().await {
                                    tracing::debug!(?e, "docs firewall policy sync");
                                }
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
        if let Some(key) = &entry.ssh_host_key {
            set_str(doc, author, peer_key(id, "ssh_host_key"), key).await?;
        }
        Ok(())
    }

    /// Publish this node's SSH host pubkey into the membership doc.
    pub async fn set_ssh_host_key(&self, openssh_pubkey: &str) -> anyhow::Result<()> {
        let key = openssh_pubkey.trim();
        if key.is_empty() {
            return Ok(());
        }
        set_str(
            &self.inner.doc,
            self.inner.author,
            peer_key(&self.inner.self_endpoint_id, "ssh_host_key"),
            key,
        )
        .await?;
        if let Some(entry) = self
            .inner
            .members
            .lock()
            .get_mut(&self.inner.self_endpoint_id)
        {
            entry.ssh_host_key = Some(key.to_string());
        }
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
            let bytes = match self.inner.blobs.get_bytes(hash).await {
                Ok(b) => b,
                Err(e) => {
                    // Missing/corrupt blob must not brick agent startup (common after
                    // partial sync, version skew, or unreachable peers).
                    tracing::warn!(
                        peer = %id,
                        %field,
                        hash = %hash,
                        error = %e,
                        "skipping unread membership blob"
                    );
                    continue;
                }
            };
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
            let ssh_host_key = f
                .get("ssh_host_key")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
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
                    ssh_host_key,
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
        policy: &tunnet_common::policy::PolicyBundle,
    ) {
        let members = self.snapshot_members();
        // Include self so PeerDNS resolves this node's hostname.
        let peers: Vec<tunnet_common::PeerEntry> = members
            .iter()
            .filter(|m| m.status != "kicked")
            .map(|m| tunnet_common::PeerEntry {
                ip: m.ipv4,
                endpoint_id: m.endpoint_id.clone(),
                hostname: m.hostname.clone(),
                tags: m.tags.clone(),
                ssh_host_key: m.ssh_host_key.clone(),
            })
            .collect();
        let version = members.len() as u64;
        let dns = (**self.inner.dns.load()).clone();
        routes.replace_network(
            self.inner.network_id,
            self.inner.join_index,
            &peers,
            &dns,
            &self.inner.network_name,
            &self.inner.self_endpoint_id,
            version,
        );
        acl.replace_bundle(policy.clone());
        for m in &members {
            if m.status != "kicked" {
                auth.insert(m.endpoint_id.clone(), self.inner.network_id);
            }
        }
        // Cache for offline CLI (upgrade, etc.).
        if let Ok(json) = serde_json::to_vec_pretty(&members) {
            let _ = std::fs::write(self.inner.paths.dir.join("direct_members_cache.json"), json);
        }
        if let Err(e) =
            crate::known_hosts::sync_known_hosts(&self.inner.paths.dir, &peers, &dns.suffix)
        {
            tracing::debug!(?e, "known_hosts sync skipped");
        }
    }

    /// Hot-reload PeerDNS settings without rebuilding membership.
    pub fn set_dns(&self, dns: DnsConfig) {
        self.inner.dns.store(Arc::new(dns));
    }

    pub fn dns_config(&self) -> DnsConfig {
        (**self.inner.dns.load()).clone()
    }

    /// Drain pending kick file written by CLI.
    pub async fn apply_pending_kicks(&self) -> anyhow::Result<()> {
        let kick_path = self
            .inner
            .paths
            .dir
            .join("direct_pending_kick")
            .join(format!("{}.json", self.inner.network_id));
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

    /// Load coordinator firewall policy from docs; verify and apply or stage as pending.
    pub async fn sync_firewall_policy(&self) -> anyhow::Result<()> {
        let Some(suggested) = self.read_suggested_policy().await? else {
            return Ok(());
        };
        let payload = crate::direct::policy_docs::canonical_payload(
            suggested.meta.version,
            &suggested.meta.timestamp,
            &suggested.global,
            &suggested.by_hostname,
        )?;
        if !crate::direct::policy_docs::verify_policy(
            &self.inner.network_secret,
            &payload,
            &suggested.meta.signature,
        ) {
            tracing::warn!("firewall policy signature invalid; ignoring");
            return Ok(());
        }

        let rules =
            crate::direct::policy_docs::effective_suggested(&suggested, &self.inner.hostname);

        if self.inner.auto_accept_firewall {
            if let Some(fw) = &self.inner.firewall {
                fw.set_suggested(rules);
            }
            let _ = std::fs::remove_file(
                self.inner
                    .paths
                    .firewall_pending_file(self.inner.network_id),
            );
        } else {
            let pending = crate::direct::policy_docs::PendingSuggestion {
                received_at: Utc::now().to_rfc3339(),
                policy: suggested,
            };
            let json = serde_json::to_vec_pretty(&pending)?;
            let pending_path = self
                .inner
                .paths
                .firewall_pending_file(self.inner.network_id);
            if let Some(parent) = pending_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(pending_path, json)?;
        }
        Ok(())
    }

    pub async fn read_suggested_policy(
        &self,
    ) -> anyhow::Result<Option<crate::direct::policy_docs::SuggestedPolicy>> {
        use crate::direct::policy_docs::{POLICY_GLOBAL_KEY, POLICY_META_KEY, policy_hostname_key};

        let meta_bytes = self.get_key_bytes(POLICY_META_KEY.as_bytes()).await?;
        let Some(meta_bytes) = meta_bytes else {
            return Ok(None);
        };
        let meta: crate::direct::policy_docs::PolicyMeta = serde_json::from_slice(&meta_bytes)?;

        let global = match self.get_key_bytes(POLICY_GLOBAL_KEY.as_bytes()).await? {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => vec![],
        };

        let mut by_hostname = HashMap::new();
        let host_key = policy_hostname_key(&self.inner.hostname);
        if let Some(b) = self.get_key_bytes(host_key.as_bytes()).await?
            && let Ok(rules) = serde_json::from_slice(&b)
        {
            by_hostname.insert(self.inner.hostname.clone(), rules);
        }

        // Also load any hostname-specific keys we find under policy/v1/hostname/
        let stream = self
            .inner
            .doc
            .get_many(Query::single_latest_per_key().key_prefix("policy/v1/hostname/"))
            .await
            .context("get_many policy hostname")?;
        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            let entry = item?;
            let key = String::from_utf8_lossy(entry.key());
            let Some(host) = key.strip_prefix("policy/v1/hostname/") else {
                continue;
            };
            if host == self.inner.hostname {
                continue; // already loaded
            }
            let hash = entry.content_hash();
            let bytes = self
                .inner
                .blobs
                .get_bytes(hash)
                .await
                .map_err(|e| anyhow::anyhow!("policy host blob: {e}"))?;
            if let Ok(rules) = serde_json::from_slice::<Vec<_>>(&bytes) {
                by_hostname.insert(host.to_string(), rules);
            }
        }

        Ok(Some(crate::direct::policy_docs::SuggestedPolicy {
            meta,
            global,
            by_hostname,
        }))
    }

    async fn get_key_bytes(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        let stream = self
            .inner
            .doc
            .get_many(Query::single_latest_per_key().key_exact(key))
            .await
            .context("get_key")?;
        tokio::pin!(stream);
        let Some(item) = stream.next().await else {
            return Ok(None);
        };
        let entry = item?;
        let hash = entry.content_hash();
        let bytes = self
            .inner
            .blobs
            .get_bytes(hash)
            .await
            .map_err(|e| anyhow::anyhow!("get key blob: {e}"))?;
        Ok(Some(bytes))
    }

    /// Coordinator: publish a suggested firewall policy into the membership doc.
    pub async fn publish_firewall_policy(
        &self,
        global: Vec<crate::direct::firewall::FirewallRule>,
        by_hostname: HashMap<String, Vec<crate::direct::firewall::FirewallRule>>,
    ) -> anyhow::Result<()> {
        use crate::direct::policy_docs::{
            POLICY_GLOBAL_KEY, POLICY_META_KEY, PolicyMeta, canonical_payload, policy_hostname_key,
            sign_policy,
        };

        let version = Utc::now().timestamp() as u64;
        let timestamp = Utc::now().to_rfc3339();
        let payload = canonical_payload(version, &timestamp, &global, &by_hostname)?;
        let signature = sign_policy(&self.inner.network_secret, &payload);
        let meta = PolicyMeta {
            version,
            timestamp,
            signature,
        };

        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_META_KEY),
            &serde_json::to_string(&meta)?,
        )
        .await?;
        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_GLOBAL_KEY),
            &serde_json::to_string(&global)?,
        )
        .await?;
        for (host, rules) in &by_hostname {
            set_str(
                &self.inner.doc,
                self.inner.author,
                Bytes::from(policy_hostname_key(host)),
                &serde_json::to_string(rules)?,
            )
            .await?;
        }
        Ok(())
    }

    /// Coordinator: clear published firewall policy keys.
    pub async fn clear_firewall_policy(&self) -> anyhow::Result<()> {
        use crate::direct::policy_docs::{POLICY_GLOBAL_KEY, POLICY_META_KEY};

        // Overwrite with empty tombstones (iroh-docs has no delete in all versions).
        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_META_KEY),
            "",
        )
        .await?;
        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_GLOBAL_KEY),
            "[]",
        )
        .await?;
        if let Some(fw) = &self.inner.firewall {
            fw.clear_suggested();
        }
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
