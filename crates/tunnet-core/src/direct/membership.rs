//! Direct-mode membership via [iroh-docs](https://github.com/n0-computer/iroh-docs).
//!
//! One document per Direct network. Keys:
//! - `meta/genesis` - network genesis (signed)
//! - `meta/epoch` - current network epoch (signed)
//! - `meta/name` - optional display metadata
//! - `peers/<endpoint_id>/record` - signed [`SignedMemberRecord`] JSON
//! - `revocations/<endpoint_id>` - signed [`Revocation`] JSON
//! - `policy/v1/bundle` - coordinator firewall policy bundle

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use iroh::protocol::ProtocolHandler;
use iroh_blobs::store::fs::FsStore;
use iroh_docs::api::Doc;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::engine::LiveEvent;
use iroh_docs::protocol::Docs;
use iroh_docs::store::Query;
use iroh_docs::{AuthorId, DocTicket, NamespaceId};
use iroh_gossip::net::Gossip;
use jiff::Timestamp;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tunnet_common::DnsConfig;
use uuid::Uuid;

use crate::acl::AclEngine;
use crate::direct::auth::AuthCache;
use crate::direct::grants::{
    EpochRecord, Genesis, MEMBER_SCHEMA_VERSION, MemberRole, NetworkGrant, Revocation,
    SignedMemberRecord, grant_expiry, sign_epoch, sign_grant, sign_member_record, sign_revocation,
    validate_member_against_genesis, verify_epoch, verify_genesis, verify_member_record,
    verify_revocation, verifying_key_from_hex,
};
use crate::routing::RoutingTable;
use crate::state::{DirectState, StatePaths};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipEntry {
    pub endpoint_id: String,
    pub hostname: String,
    pub ipv4: Ipv4Addr,
    #[serde(default)]
    pub tags: Vec<String>,
    pub joined_at: Timestamp,
    #[serde(default)]
    pub coordinator: bool,
    #[serde(default = "default_active")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
}

fn default_active() -> String {
    "active".into()
}

fn genesis_key() -> Bytes {
    Bytes::from("meta/genesis")
}

fn epoch_key() -> Bytes {
    Bytes::from("meta/epoch")
}

fn meta_key(field: &str) -> Bytes {
    Bytes::from(format!("meta/{field}"))
}

fn record_key(endpoint_id: &str) -> Bytes {
    Bytes::from(format!("peers/{endpoint_id}/record"))
}

fn revocation_key(endpoint_id: &str) -> Bytes {
    Bytes::from(format!("revocations/{endpoint_id}"))
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
    network_name: String,
    genesis: parking_lot::RwLock<Option<Genesis>>,
    join_secret: String,
    coordinator_signing_key: Option<SigningKey>,
    coordinator_verifying_key: String,
    network_epoch: Arc<AtomicU64>,
    content_key: String,
    revoked: Arc<Mutex<HashSet<String>>>,
    self_grant: Option<NetworkGrant>,
    #[allow(dead_code)]
    endpoint_signing_key: SigningKey,
    hostname: String,
    auto_accept_firewall: bool,
    self_endpoint_id: String,
    paths: StatePaths,
    firewall: Option<crate::direct::FirewallEngine>,
    dns: Arc<ArcSwap<DnsConfig>>,
    /// Shared with [`crate::direct::spawn_seed_auth`] so membership updates refresh dials.
    seed_peers: Arc<Mutex<Vec<String>>>,
    coordinator_endpoint_id: Option<String>,
}

/// Inputs for [`DocsMembership::bootstrap`].
pub struct DocsBootstrap<'a> {
    pub docs: Docs,
    pub gossip: Gossip,
    pub paths: &'a StatePaths,
    pub direct: &'a DirectState,
    pub self_endpoint_id: &'a str,
    pub self_entry: MembershipEntry,
    pub endpoint_signing_key: SigningKey,
    pub coordinator_signing_key: Option<SigningKey>,
    pub coordinator_verifying_key: String,
    pub content_key: String,
    pub network_grant: Option<NetworkGrant>,
    pub blobs: FsStore,
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub auth: AuthCache,
    pub policy: tunnet_common::policy::PolicyBundle,
    pub firewall: Option<crate::direct::FirewallEngine>,
    pub dns: DnsConfig,
    pub seed_peers: Arc<Mutex<Vec<String>>>,
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

    pub fn network_epoch(&self) -> u64 {
        self.inner.network_epoch.load(Ordering::Relaxed)
    }

    pub fn revoked_snapshot(&self) -> HashSet<String> {
        self.inner.revoked.lock().clone()
    }

    pub fn coordinator_verifying_key(&self) -> &str {
        &self.inner.coordinator_verifying_key
    }

    pub fn join_secret(&self) -> &str {
        &self.inner.join_secret
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

    pub async fn share_read_ticket(&self) -> anyhow::Result<String> {
        let ticket = self
            .inner
            .doc
            .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
            .await
            .context("share read ticket")?;
        Ok(ticket.to_string())
    }

    pub async fn bootstrap(
        cfg: DocsBootstrap<'_>,
    ) -> anyhow::Result<(Self, Option<String>, Option<String>)> {
        let DocsBootstrap {
            docs,
            gossip,
            paths,
            direct,
            self_endpoint_id,
            self_entry,
            endpoint_signing_key,
            coordinator_signing_key,
            coordinator_verifying_key,
            content_key,
            network_grant,
            blobs,
            routes,
            acl,
            auth,
            policy,
            firewall,
            dns,
            seed_peers,
        } = cfg;
        paths.ensure_network_dirs(direct.network_id)?;

        let author = docs.author_default().await.context("default author")?;
        let network_epoch = Arc::new(AtomicU64::new(direct.network_epoch));
        let revoked = Arc::new(Mutex::new(HashSet::new()));

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
                .context("open namespace on unified docs engine")?
                .context(
                    "namespace not found in unified docs store; re-join with a fresh doc ticket",
                )?;
            (doc, None, Some(ns.clone()))
        } else if direct.coordinator {
            let doc = docs.create().await.context("create membership doc")?;
            let ticket = doc
                .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
                .await
                .context("share new doc")?;
            let ns = doc.id().to_string();
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
                network_name: direct.network_name.clone(),
                genesis: parking_lot::RwLock::new(Some(direct.genesis.clone())),
                join_secret: direct.join_secret.clone(),
                coordinator_signing_key,
                coordinator_verifying_key,
                network_epoch: network_epoch.clone(),
                content_key,
                revoked: revoked.clone(),
                self_grant: network_grant,
                endpoint_signing_key,
                hostname: direct.hostname.clone(),
                auto_accept_firewall: direct.auto_accept_firewall,
                self_endpoint_id: self_endpoint_id.to_string(),
                paths: paths.clone_paths(),
                firewall,
                dns: Arc::new(ArcSwap::from_pointee(dns)),
                seed_peers: seed_peers.clone(),
                coordinator_endpoint_id: direct.coordinator_endpoint_id.clone(),
            }),
        };

        if direct.coordinator && direct.doc_ticket.is_none() && direct.namespace_id.is_none() {
            membership.publish_genesis(&direct.genesis).await?;
            membership
                .write_self_record(&self_entry)
                .await
                .context("write coordinator self record")?;
        }

        membership.rebuild_from_doc().await?;
        membership.apply_to_routes(&routes, &acl, &policy);
        membership.refresh_seed_peers();
        if let Err(e) = membership.sync_firewall_policy().await {
            tracing::debug!(?e, "initial firewall policy sync");
        }
        if let Err(e) = membership.apply_pending_kicks(&auth).await {
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
                                bg.apply_to_routes(&routes_bg, &acl_bg, &policy_bg);
                                bg.refresh_seed_peers();
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
                        let _ = bg.apply_pending_kicks(&auth_bg).await;
                    }
                }
            }
        });

        Ok((membership, created_ticket, namespace_str))
    }

    pub async fn publish_genesis(&self, genesis: &Genesis) -> anyhow::Result<()> {
        let coord_vk = verifying_key_from_hex(&self.inner.coordinator_verifying_key)
            .context("coordinator verifying key")?;
        verify_genesis(&coord_vk, genesis)?;
        if genesis.network_id != self.inner.network_id {
            anyhow::bail!("genesis network_id mismatch");
        }
        set_json(&self.inner.doc, self.inner.author, genesis_key(), genesis).await?;

        let epoch = if let Some(sk) = &self.inner.coordinator_signing_key {
            sign_epoch(
                sk,
                EpochRecord {
                    network_epoch: 0,
                    sig: String::new(),
                },
            )?
        } else {
            anyhow::bail!("coordinator signing key required to publish genesis");
        };
        set_json(&self.inner.doc, self.inner.author, epoch_key(), &epoch).await?;
        self.inner.network_epoch.store(0, Ordering::Relaxed);

        set_str(
            &self.inner.doc,
            self.inner.author,
            meta_key("name"),
            &self.inner.network_name,
        )
        .await?;
        *self.inner.genesis.write() = Some(genesis.clone());
        Ok(())
    }

    pub fn genesis(&self) -> Option<Genesis> {
        self.inner.genesis.read().clone()
    }

    async fn write_self_record(&self, entry: &MembershipEntry) -> anyhow::Result<()> {
        let grant = if let Some(g) = &self.inner.self_grant {
            g.clone()
        } else {
            self.issue_grant(
                &entry.endpoint_id,
                if entry.coordinator {
                    MemberRole::Coordinator
                } else {
                    MemberRole::Member
                },
            )?
        };
        let record = self.build_record(entry, grant, 1)?;
        self.write_member_record(&record).await
    }

    fn issue_grant(&self, endpoint_id: &str, role: MemberRole) -> anyhow::Result<NetworkGrant> {
        let Some(sk) = &self.inner.coordinator_signing_key else {
            anyhow::bail!("coordinator signing key not configured");
        };
        let epoch = self.inner.network_epoch.load(Ordering::Relaxed);
        let now = Timestamp::now();
        sign_grant(
            sk,
            NetworkGrant {
                network_id: self.inner.network_id,
                endpoint_id: endpoint_id.to_string(),
                role,
                network_epoch: epoch,
                issued_at: now,
                expires_at: grant_expiry(now)?,
                content_key: self.inner.content_key.clone(),
                sig: String::new(),
            },
        )
    }

    fn build_record(
        &self,
        entry: &MembershipEntry,
        grant: NetworkGrant,
        sequence: u64,
    ) -> anyhow::Result<SignedMemberRecord> {
        let Some(sk) = &self.inner.coordinator_signing_key else {
            anyhow::bail!("coordinator signing key not configured");
        };
        let record = SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id: self.inner.network_id,
            endpoint_id: entry.endpoint_id.clone(),
            hostname: entry.hostname.clone(),
            ipv4: entry.ipv4,
            tags: entry.tags.clone(),
            status: entry.status.clone(),
            ssh_host_key: entry.ssh_host_key.clone(),
            sequence,
            joined_at: entry.joined_at,
            grant,
            endpoint_sig: String::new(),
            coordinator: entry.coordinator,
        };
        sign_member_record(sk, record)
    }

    async fn write_member_record(&self, record: &SignedMemberRecord) -> anyhow::Result<()> {
        set_json(
            &self.inner.doc,
            self.inner.author,
            record_key(&record.endpoint_id),
            record,
        )
        .await
    }

    /// Coordinator admits a joiner: issue grant + signed member record.
    ///
    /// Inserts the joiner into [`AuthCache`] so the data plane can dial immediately
    /// (Invite AUTH already succeeded on this connection; Grant AUTH would race the
    /// joiner restart).
    pub async fn admit_peer(
        &self,
        entry: &MembershipEntry,
        auth: &AuthCache,
    ) -> anyhow::Result<(NetworkGrant, String, SignedMemberRecord)> {
        let grant = self.issue_grant(
            &entry.endpoint_id,
            if entry.coordinator {
                MemberRole::Coordinator
            } else {
                MemberRole::Member
            },
        )?;
        let sequence = self
            .inner
            .members
            .lock()
            .get(&entry.endpoint_id)
            .map(|_| 2)
            .unwrap_or(1);
        let record = self.build_record(entry, grant.clone(), sequence)?;
        self.write_member_record(&record).await?;
        self.inner
            .members
            .lock()
            .insert(entry.endpoint_id.clone(), entry.clone());
        auth.insert(entry.endpoint_id.clone(), self.inner.network_id);
        Ok((grant, self.inner.content_key.clone(), record))
    }

    /// Publish this node's SSH host pubkey by updating the self member record.
    pub async fn set_ssh_host_key(&self, openssh_pubkey: &str) -> anyhow::Result<()> {
        let key = openssh_pubkey.trim();
        if key.is_empty() {
            return Ok(());
        }
        let entry = {
            let mut members = self.inner.members.lock();
            let Some(entry) = members.get_mut(&self.inner.self_endpoint_id) else {
                return Ok(());
            };
            entry.ssh_host_key = Some(key.to_string());
            entry.clone()
        };
        if self.inner.coordinator_signing_key.is_some() {
            self.write_self_record(&entry).await?;
        }
        Ok(())
    }

    /// Coordinator revokes a peer: bump epoch, write revocation + kicked record.
    pub async fn kick_peer(&self, endpoint_id: &str, auth: &AuthCache) -> anyhow::Result<()> {
        let Some(sk) = &self.inner.coordinator_signing_key else {
            anyhow::bail!("coordinator signing key not configured");
        };

        let new_epoch = self.inner.network_epoch.load(Ordering::Relaxed) + 1;
        let epoch = sign_epoch(
            sk,
            EpochRecord {
                network_epoch: new_epoch,
                sig: String::new(),
            },
        )?;
        set_json(&self.inner.doc, self.inner.author, epoch_key(), &epoch).await?;
        self.inner.network_epoch.store(new_epoch, Ordering::Relaxed);

        let revocation = sign_revocation(
            sk,
            Revocation {
                endpoint_id: endpoint_id.to_string(),
                network_epoch: new_epoch,
                reason: "kicked".into(),
                sig: String::new(),
            },
        )?;
        set_json(
            &self.inner.doc,
            self.inner.author,
            revocation_key(endpoint_id),
            &revocation,
        )
        .await?;
        self.inner.revoked.lock().insert(endpoint_id.to_string());

        // Do not issue a new grant for the kicked peer - epoch bump invalidates
        // prior grants; revocation blocks Invite/Grant AUTH.
        auth.remove_network(endpoint_id, self.inner.network_id);
        self.inner.members.lock().remove(endpoint_id);
        Ok(())
    }

    pub async fn rebuild_from_doc(&self) -> anyhow::Result<()> {
        let coord_vk = verifying_key_from_hex(&self.inner.coordinator_verifying_key)
            .context("coordinator verifying key")?;

        let genesis = if let Some(bytes) = self.get_key_bytes(&genesis_key()).await? {
            let genesis: Genesis = serde_json::from_slice(&bytes).map_err(|_| {
                anyhow::anyhow!("unsupported legacy Direct network: recreate with `tunnet create`")
            })?;
            verify_genesis(&coord_vk, &genesis)?;
            if genesis.network_id != self.inner.network_id {
                anyhow::bail!("genesis network_id mismatch");
            }
            if let Some(local) = self.inner.genesis.read().clone()
                && local.address_plan != genesis.address_plan
            {
                anyhow::bail!("genesis address plan mismatch");
            }
            *self.inner.genesis.write() = Some(genesis.clone());
            genesis
        } else if let Some(local) = self.inner.genesis.read().clone() {
            local
        } else {
            anyhow::bail!("missing genesis; recreate with `tunnet create`");
        };

        let mut min_epoch = 0u64;
        if let Some(bytes) = self.get_key_bytes(&epoch_key()).await? {
            let epoch: EpochRecord = serde_json::from_slice(&bytes)?;
            verify_epoch(&coord_vk, &epoch)?;
            min_epoch = epoch.network_epoch;
            self.inner
                .network_epoch
                .store(epoch.network_epoch, Ordering::Relaxed);
        }

        let mut revoked = HashSet::new();
        let rev_stream = self
            .inner
            .doc
            .get_many(Query::single_latest_per_key().key_prefix("revocations/"))
            .await
            .context("get_many revocations")?;
        tokio::pin!(rev_stream);
        while let Some(item) = rev_stream.next().await {
            let entry = item.context("revocation entry")?;
            let key = std::str::from_utf8(entry.key()).unwrap_or("");
            let Some(endpoint_id) = key.strip_prefix("revocations/") else {
                continue;
            };
            let hash = entry.content_hash();
            let bytes = match self.inner.blobs.get_bytes(hash).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(%endpoint_id, hash = %hash, error = %e, "skipping unread revocation blob");
                    continue;
                }
            };
            let revocation: Revocation = serde_json::from_slice(&bytes)?;
            if verify_revocation(&coord_vk, &revocation).is_ok() {
                revoked.insert(endpoint_id.to_string());
            }
        }
        *self.inner.revoked.lock() = revoked.clone();

        let stream = self
            .inner
            .doc
            .get_many(Query::single_latest_per_key().key_prefix("peers/"))
            .await
            .context("get_many peers")?;
        tokio::pin!(stream);

        let mut map = HashMap::new();
        while let Some(item) = stream.next().await {
            let entry = item.context("peer entry")?;
            let key = std::str::from_utf8(entry.key()).unwrap_or("");
            let Some(rest) = key.strip_prefix("peers/") else {
                continue;
            };
            let Some((endpoint_id, field)) = rest.split_once('/') else {
                continue;
            };
            if field != "record" {
                continue;
            }
            if revoked.contains(endpoint_id) {
                continue;
            }
            let hash = entry.content_hash();
            let bytes = match self.inner.blobs.get_bytes(hash).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        peer = %endpoint_id,
                        hash = %hash,
                        error = %e,
                        "skipping unread member record blob"
                    );
                    continue;
                }
            };
            let record: SignedMemberRecord = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(peer = %endpoint_id, error = %e, "invalid member record json");
                    continue;
                }
            };
            if verify_member_record(&coord_vk, &record, min_epoch).is_err() {
                tracing::warn!(peer = %endpoint_id, "member record verification failed");
                continue;
            }
            if validate_member_against_genesis(&genesis, &record).is_err() {
                tracing::warn!(peer = %endpoint_id, "member record outside address plan");
                continue;
            }
            if record.status == "kicked" || revoked.contains(&record.endpoint_id) {
                continue;
            }
            map.insert(
                endpoint_id.to_string(),
                MembershipEntry {
                    endpoint_id: record.endpoint_id,
                    hostname: record.hostname,
                    ipv4: record.ipv4,
                    tags: record.tags,
                    joined_at: record.joined_at,
                    coordinator: record.coordinator,
                    status: "active".into(),
                    ssh_host_key: record.ssh_host_key,
                },
            );
        }
        {
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            map.retain(|_, m| seen.insert(m.ipv4));
        }
        *self.inner.members.lock() = map;
        Ok(())
    }

    pub fn apply_to_routes(
        &self,
        routes: &RoutingTable,
        acl: &AclEngine,
        policy: &tunnet_common::policy::PolicyBundle,
    ) {
        let members = self.snapshot_members();
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
        let peer_cidr = self
            .inner
            .genesis
            .read()
            .clone()
            .map(|g| g.address_plan.peer_cidr);
        routes.replace_network_with_plan(
            self.inner.network_id,
            &peers,
            &dns,
            &self.inner.network_name,
            &self.inner.self_endpoint_id,
            version,
            peer_cidr,
        );
        acl.replace_bundle(policy.clone());
        if let Ok(json) = serde_json::to_vec_pretty(&members) {
            let _ = std::fs::write(self.inner.paths.dir.join("direct_members_cache.json"), json);
        }
        if let Err(e) =
            crate::known_hosts::sync_known_hosts(&self.inner.paths.dir, &peers, &dns.suffix)
        {
            tracing::debug!(?e, "known_hosts sync skipped");
        }
    }

    /// Keep Grant AUTH seed dials in sync with verified membership.
    pub fn refresh_seed_peers(&self) {
        let mut seeds: Vec<String> = self
            .snapshot_members()
            .into_iter()
            .map(|m| m.endpoint_id)
            .filter(|id| id != &self.inner.self_endpoint_id)
            .collect();
        if let Some(coord) = &self.inner.coordinator_endpoint_id
            && coord != &self.inner.self_endpoint_id
            && !seeds.iter().any(|s| s == coord)
        {
            seeds.push(coord.clone());
        }
        seeds.sort();
        seeds.dedup();
        *self.inner.seed_peers.lock() = seeds;
    }

    pub fn set_dns(&self, dns: DnsConfig) {
        self.inner.dns.store(Arc::new(dns));
    }

    pub fn dns_config(&self) -> DnsConfig {
        (**self.inner.dns.load()).clone()
    }

    pub async fn apply_pending_kicks(&self, auth: &AuthCache) -> anyhow::Result<()> {
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
            self.kick_peer(id, auth).await?;
        }
        let _ = std::fs::remove_file(&kick_path);
        Ok(())
    }

    pub async fn sync_firewall_policy(&self) -> anyhow::Result<()> {
        let Some(suggested) = self.read_suggested_policy().await? else {
            return Ok(());
        };
        if let Ok(vk) = verifying_key_from_hex(&self.inner.coordinator_verifying_key) {
            if crate::direct::policy_docs::verify_policy_bundle(&vk, &suggested).is_err() {
                tracing::warn!("firewall policy signature invalid; ignoring");
                return Ok(());
            }
        } else {
            tracing::warn!("coordinator verifying key invalid; skipping policy signature check");
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
                received_at: Timestamp::now(),
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
        use crate::direct::policy_docs::POLICY_BUNDLE_KEY;

        let bundle_bytes = self.get_key_bytes(POLICY_BUNDLE_KEY.as_bytes()).await?;
        let Some(bundle_bytes) = bundle_bytes else {
            return Ok(None);
        };
        if bundle_bytes.is_empty() {
            return Ok(None);
        }
        let bundle: crate::direct::policy_docs::PolicyBundleDoc =
            serde_json::from_slice(&bundle_bytes)?;
        Ok(Some(bundle))
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

    pub async fn publish_firewall_policy(
        &self,
        global: Vec<crate::direct::firewall::FirewallRule>,
        by_hostname: HashMap<String, Vec<crate::direct::firewall::FirewallRule>>,
    ) -> anyhow::Result<()> {
        use crate::direct::policy_docs::{POLICY_BUNDLE_KEY, sign_policy_bundle};

        let Some(sk) = &self.inner.coordinator_signing_key else {
            anyhow::bail!("coordinator signing key not configured");
        };

        let now = Timestamp::now();
        let version = u64::try_from(now.as_second()).unwrap_or_default();
        let timestamp = now;
        let bundle = sign_policy_bundle(sk, version, timestamp, global, by_hostname)?;

        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_BUNDLE_KEY),
            &serde_json::to_string(&bundle)?,
        )
        .await?;
        Ok(())
    }

    pub async fn clear_firewall_policy(&self) -> anyhow::Result<()> {
        use crate::direct::policy_docs::POLICY_BUNDLE_KEY;

        set_str(
            &self.inner.doc,
            self.inner.author,
            Bytes::from(POLICY_BUNDLE_KEY),
            "",
        )
        .await?;
        if let Some(fw) = &self.inner.firewall {
            fw.clear_suggested();
        }
        Ok(())
    }

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

async fn set_str(doc: &Doc, author: AuthorId, key: Bytes, value: &str) -> anyhow::Result<()> {
    doc.set_bytes(author, key, Bytes::copy_from_slice(value.as_bytes()))
        .await
        .context("doc set_bytes")?;
    Ok(())
}

async fn set_json<T: Serialize>(
    doc: &Doc,
    author: AuthorId,
    key: Bytes,
    value: &T,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(value)?;
    doc.set_bytes(author, key, Bytes::from(json))
        .await
        .context("doc set_bytes")?;
    Ok(())
}

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
