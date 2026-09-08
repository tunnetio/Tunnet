//! Coordinator-authoritative Direct join state.
//!
//! One [`DirectAuthority`] per coordinator network owns invites, pending joins,
//! admission reservations, and claim records. Membership documents, AuthCache,
//! routes, ACL, and seed peers are derived projections updated after admission.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use jiff::{Span, Timestamp};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::addrplan::{AddressPlan, allocate_peer_ip};
use super::grants::Genesis;
use super::invite::{InviteCode, invite_secret_hash};
use super::membership::MembershipEntry;
use crate::state::StatePaths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJoin {
    pub endpoint_id: String,
    pub hostname: String,
    pub invite_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteRecord {
    secret_hash: String,
    reusable: bool,
    expires_at: Timestamp,
    revoked: bool,
    /// One-time: first presenter is bound so retries recover and other endpoints fail.
    bound_endpoint: Option<String>,
    allocated_ip: Option<Ipv4Addr>,
    claimed: bool,
    created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorityDisk {
    network_id: Uuid,
    open: bool,
    invites: HashMap<String, InviteRecord>,
    pending: Vec<PendingJoin>,
    approved: HashSet<String>,
}

struct Inner {
    disk: AuthorityDisk,
    path: PathBuf,
}

/// Exclusive mutator of join/invite/admission state for one coordinator network.
#[derive(Clone)]
pub struct DirectAuthority {
    inner: Arc<Mutex<Inner>>,
    pub network_id: Uuid,
    genesis: Genesis,
    topic_hash: String,
}

#[derive(Debug, Clone)]
pub struct JoinSnapshot {
    pub members: Vec<MembershipEntry>,
    pub revoked: HashSet<String>,
}

#[derive(Debug, Clone)]
pub enum JoinDecision {
    Denied {
        reason: &'static str,
    },
    Pending,
    Admit {
        entry: MembershipEntry,
        /// Membership record already exists; republish artifacts only.
        recover: bool,
    },
}

impl DirectAuthority {
    pub fn load(
        paths: &StatePaths,
        network_id: Uuid,
        open: bool,
        genesis: Genesis,
        topic_hash: String,
    ) -> anyhow::Result<Self> {
        paths.ensure_network_dirs(network_id)?;
        let path = paths.authority_file(network_id);
        let disk = if path.exists() {
            let mut disk: AuthorityDisk =
                serde_json::from_slice(&std::fs::read(&path)?).context("authority state")?;
            disk.open = open;
            disk.network_id = network_id;
            disk
        } else {
            AuthorityDisk {
                network_id,
                open,
                invites: HashMap::new(),
                pending: Vec::new(),
                approved: HashSet::new(),
            }
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { disk, path })),
            network_id,
            genesis,
            topic_hash,
        })
    }

    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    pub fn topic_hash(&self) -> &str {
        &self.topic_hash
    }

    pub fn address_plan(&self) -> AddressPlan {
        self.genesis.address_plan
    }

    pub async fn pending(&self) -> Vec<PendingJoin> {
        self.inner.lock().await.disk.pending.clone()
    }

    pub async fn issue_invite(
        &self,
        _coordinator_endpoint_id: &str,
        reusable: bool,
        expires: Span,
    ) -> anyhow::Result<InviteCode> {
        if !expires.is_positive() {
            anyhow::bail!("invite expiry must be positive");
        }
        let expires_at = Timestamp::now()
            .checked_add(expires)
            .context("invite expiry is outside the representable timestamp range")?;
        let secret = hex::encode(rand::random::<[u8; 32]>());
        let secret_hash = invite_secret_hash(&secret);
        let rec = InviteRecord {
            secret_hash: secret_hash.clone(),
            reusable,
            expires_at,
            revoked: false,
            bound_endpoint: None,
            allocated_ip: None,
            claimed: false,
            created_at: Timestamp::now(),
        };
        {
            let mut g = self.inner.lock().await;
            g.disk.invites.insert(secret_hash, rec);
            persist(&g)?;
        }
        Ok(InviteCode {
            genesis: self.genesis.clone(),
            invite_secret: secret,
            expires_at,
        })
    }

    pub async fn revoke_invite_secret(&self, invite_secret: &str) -> anyhow::Result<()> {
        let hash = invite_secret_hash(invite_secret);
        let mut g = self.inner.lock().await;
        let Some(rec) = g.disk.invites.get_mut(&hash) else {
            anyhow::bail!("unknown invite");
        };
        rec.revoked = true;
        persist(&g)
    }

    pub async fn approve(&self, endpoint_id: &str) -> anyhow::Result<PendingJoin> {
        let mut g = self.inner.lock().await;
        let idx = g
            .disk
            .pending
            .iter()
            .position(|p| p.endpoint_id == endpoint_id || p.hostname == endpoint_id)
            .context("pending peer not found")?;
        let pending = g.disk.pending.remove(idx);
        g.disk.approved.insert(pending.endpoint_id.clone());
        persist(&g)?;
        Ok(pending)
    }

    pub async fn deny(&self, endpoint_id: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock().await;
        let before = g.disk.pending.len();
        g.disk
            .pending
            .retain(|p| p.endpoint_id != endpoint_id && p.hostname != endpoint_id);
        if g.disk.pending.len() == before {
            anyhow::bail!("pending peer not found");
        }
        persist(&g)
    }

    pub async fn has_invite_secret(&self, invite_secret: &str) -> bool {
        let hash = invite_secret_hash(invite_secret);
        self.inner.lock().await.disk.invites.contains_key(&hash)
    }

    /// Persist invite bind / IP reservation. Caller publishes membership, then [`Self::confirm`].
    pub async fn decide(
        &self,
        endpoint_id: &str,
        hostname: String,
        invite_secret: &str,
        snapshot: &JoinSnapshot,
    ) -> JoinDecision {
        let mut g = self.inner.lock().await;
        match decide_locked(
            &mut g,
            &self.genesis,
            endpoint_id,
            hostname,
            invite_secret,
            snapshot,
        ) {
            Ok(d) => d,
            Err(reason) => JoinDecision::Denied { reason },
        }
    }

    pub async fn confirm(&self, endpoint_id: &str, ipv4: Ipv4Addr) -> anyhow::Result<()> {
        let mut g = self.inner.lock().await;
        g.disk.approved.remove(endpoint_id);
        g.disk.pending.retain(|p| p.endpoint_id != endpoint_id);
        for rec in g.disk.invites.values_mut() {
            if rec.bound_endpoint.as_deref() == Some(endpoint_id) {
                rec.claimed = true;
                rec.allocated_ip = Some(ipv4);
            }
        }
        persist(&g)
    }
}

fn persist(inner: &Inner) -> anyhow::Result<()> {
    if let Some(parent) = inner.path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&inner.path, serde_json::to_vec_pretty(&inner.disk)?)?;
    Ok(())
}

fn decide_locked(
    inner: &mut Inner,
    genesis: &Genesis,
    endpoint_id: &str,
    hostname: String,
    invite_secret: &str,
    snapshot: &JoinSnapshot,
) -> Result<JoinDecision, &'static str> {
    let hash = invite_secret_hash(invite_secret);
    let now = Timestamp::now();
    let open = inner.disk.open;

    let rec = inner
        .disk
        .invites
        .get_mut(&hash)
        .ok_or("invalid_or_used_invite")?;
    if rec.revoked {
        return Err("invite_revoked");
    }
    if rec.expires_at < now {
        return Err("invite_expired");
    }
    if snapshot.revoked.contains(endpoint_id) {
        return Err("revoked");
    }

    if !rec.reusable {
        if let Some(bound) = rec.bound_endpoint.as_deref()
            && bound != endpoint_id
        {
            return Err("invite_claimed");
        }
        rec.bound_endpoint = Some(endpoint_id.to_string());
    }

    if let Some(existing) = snapshot
        .members
        .iter()
        .find(|m| m.endpoint_id == endpoint_id && m.status != "kicked")
    {
        rec.allocated_ip = Some(existing.ipv4);
        rec.claimed = true;
        persist(inner).map_err(|_| "persist_failed")?;
        let mut entry = existing.clone();
        entry.hostname = hostname;
        return Ok(JoinDecision::Admit {
            entry,
            recover: true,
        });
    }

    if !rec.reusable
        && rec.claimed
        && rec.bound_endpoint.as_deref() == Some(endpoint_id)
        && let Some(ip) = rec.allocated_ip
    {
        persist(inner).map_err(|_| "persist_failed")?;
        return Ok(JoinDecision::Admit {
            entry: MembershipEntry {
                endpoint_id: endpoint_id.to_string(),
                hostname,
                ipv4: ip,
                tags: vec![],
                joined_at: existing_joined_or_now(snapshot, endpoint_id),
                coordinator: false,
                status: "active".into(),
                ssh_host_key: None,
            },
            recover: false,
        });
    }

    let approved = inner.disk.approved.contains(endpoint_id);
    if !open && !approved {
        inner.disk.pending.retain(|p| p.endpoint_id != endpoint_id);
        inner.disk.pending.push(PendingJoin {
            endpoint_id: endpoint_id.to_string(),
            hostname,
            invite_hash: hash,
        });
        persist(inner).map_err(|_| "persist_failed")?;
        return Ok(JoinDecision::Pending);
    }

    let ipv4 = if let Some(ip) = rec.allocated_ip {
        ip
    } else {
        let occupied: HashSet<Ipv4Addr> = snapshot.members.iter().map(|m| m.ipv4).collect();
        allocate_peer_ip(
            &genesis.address_plan,
            &genesis.network_id,
            endpoint_id,
            &occupied,
        )
        .map_err(|_| "pool_exhausted")?
    };
    rec.allocated_ip = Some(ipv4);
    persist(inner).map_err(|_| "persist_failed")?;

    Ok(JoinDecision::Admit {
        entry: MembershipEntry {
            endpoint_id: endpoint_id.to_string(),
            hostname,
            ipv4,
            tags: vec![],
            joined_at: Timestamp::now(),
            coordinator: false,
            status: "active".into(),
            ssh_host_key: None,
        },
        recover: false,
    })
}

fn existing_joined_or_now(snapshot: &JoinSnapshot, endpoint_id: &str) -> Timestamp {
    snapshot
        .members
        .iter()
        .find(|m| m.endpoint_id == endpoint_id)
        .map(|m| m.joined_at)
        .unwrap_or_else(Timestamp::now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct::addrplan::select_peer_cidr;
    use crate::direct::grants::{
        GENESIS_SCHEMA_VERSION, generate_coordinator_keypair, sign_genesis,
    };

    fn genesis() -> Genesis {
        let (sk, vk) = generate_coordinator_keypair();
        let cidr = select_peer_cidr(&[], &[]).unwrap();
        sign_genesis(
            &sk,
            Genesis {
                schema_version: GENESIS_SCHEMA_VERSION,
                network_id: Uuid::new_v4(),
                network_name: "t".into(),
                coordinator_endpoint_id: "aa".repeat(32),
                coordinator_verifying_key: hex::encode(vk.to_bytes()),
                address_plan: cidr,
                created_at: Timestamp::now(),
                sig: String::new(),
            },
        )
        .unwrap()
    }

    fn tmp_auth(open: bool) -> (tempfile::TempDir, DirectAuthority, Genesis) {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::from_dir(dir.path().to_path_buf());
        let g = genesis();
        let auth =
            DirectAuthority::load(&paths, g.network_id, open, g.clone(), "tt".into()).unwrap();
        (dir, auth, g)
    }

    fn empty_snap() -> JoinSnapshot {
        JoinSnapshot {
            members: vec![],
            revoked: HashSet::new(),
        }
    }

    #[tokio::test]
    async fn one_time_retry_same_endpoint_reuses_ip() {
        let (_d, auth, _) = tmp_auth(true);
        let inv = auth
            .issue_invite("aa".repeat(32).as_str(), false, Span::new().hours(24))
            .await
            .unwrap();
        let d1 = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &empty_snap())
            .await;
        let JoinDecision::Admit { entry, recover } = d1 else {
            panic!("{d1:?}");
        };
        assert!(!recover);
        auth.confirm("endpoint-a", entry.ipv4).await.unwrap();

        let snap = JoinSnapshot {
            members: vec![entry.clone()],
            revoked: HashSet::new(),
        };
        let d2 = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &snap)
            .await;
        let JoinDecision::Admit {
            entry: e2,
            recover: r2,
        } = d2
        else {
            panic!("{d2:?}");
        };
        assert!(r2);
        assert_eq!(e2.ipv4, entry.ipv4);
    }

    #[tokio::test]
    async fn one_time_replay_other_endpoint_denied() {
        let (_d, auth, _) = tmp_auth(true);
        let inv = auth
            .issue_invite("c", false, Span::new().hours(24))
            .await
            .unwrap();
        let JoinDecision::Admit { entry, .. } = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &empty_snap())
            .await
        else {
            panic!("expected admit");
        };
        auth.confirm("endpoint-a", entry.ipv4).await.unwrap();
        let d = auth
            .decide("endpoint-b", "b".into(), &inv.invite_secret, &empty_snap())
            .await;
        assert!(matches!(
            d,
            JoinDecision::Denied {
                reason: "invite_claimed"
            }
        ));
    }

    #[tokio::test]
    async fn lost_response_before_confirm_reuses_reserved_ip() {
        let (_d, auth, _) = tmp_auth(true);
        let inv = auth
            .issue_invite("c", false, Span::new().hours(24))
            .await
            .unwrap();
        let JoinDecision::Admit { entry: e1, .. } = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &empty_snap())
            .await
        else {
            panic!("admit");
        };
        // Crash: membership unpublished, invite reserved. Retry must not allocate a new IP.
        let d2 = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &empty_snap())
            .await;
        let JoinDecision::Admit { entry: e2, .. } = d2 else {
            panic!("{d2:?}");
        };
        assert_eq!(e1.ipv4, e2.ipv4);
    }

    #[tokio::test]
    async fn pending_then_approve_then_join() {
        let (_d, auth, _) = tmp_auth(false);
        let inv = auth
            .issue_invite("c", false, Span::new().hours(24))
            .await
            .unwrap();
        let d1 = auth
            .decide(
                "endpoint-a",
                "host".into(),
                &inv.invite_secret,
                &empty_snap(),
            )
            .await;
        assert!(matches!(d1, JoinDecision::Pending));
        auth.approve("endpoint-a").await.unwrap();
        let d2 = auth
            .decide(
                "endpoint-a",
                "host".into(),
                &inv.invite_secret,
                &empty_snap(),
            )
            .await;
        assert!(matches!(d2, JoinDecision::Admit { recover: false, .. }));
    }

    #[tokio::test]
    async fn pending_binds_one_time_invite() {
        let (_d, auth, _) = tmp_auth(false);
        let inv = auth
            .issue_invite("c", false, Span::new().hours(24))
            .await
            .unwrap();
        let _ = auth
            .decide("endpoint-a", "a".into(), &inv.invite_secret, &empty_snap())
            .await;
        let d = auth
            .decide("endpoint-b", "b".into(), &inv.invite_secret, &empty_snap())
            .await;
        assert!(matches!(
            d,
            JoinDecision::Denied {
                reason: "invite_claimed"
            }
        ));
    }

    #[tokio::test]
    async fn expired_and_revoked() {
        let (_d, auth, _) = tmp_auth(true);
        let inv = auth
            .issue_invite("c", true, Span::new().hours(1))
            .await
            .unwrap();
        {
            let mut g = auth.inner.lock().await;
            let hash = crate::direct::invite::invite_secret_hash(&inv.invite_secret);
            g.disk.invites.get_mut(&hash).unwrap().expires_at =
                Timestamp::now() - jiff::SignedDuration::from_hours(1);
            persist(&g).unwrap();
        }
        let d = auth
            .decide("e", "h".into(), &inv.invite_secret, &empty_snap())
            .await;
        assert!(matches!(
            d,
            JoinDecision::Denied {
                reason: "invite_expired"
            }
        ));

        let inv2 = auth
            .issue_invite("c", true, Span::new().hours(1))
            .await
            .unwrap();
        auth.revoke_invite_secret(&inv2.invite_secret)
            .await
            .unwrap();
        let d = auth
            .decide("e", "h".into(), &inv2.invite_secret, &empty_snap())
            .await;
        assert!(matches!(
            d,
            JoinDecision::Denied {
                reason: "invite_revoked"
            }
        ));
    }

    #[tokio::test]
    async fn revoked_peer_cannot_rejoin() {
        let (_d, auth, _) = tmp_auth(true);
        let inv = auth
            .issue_invite("c", true, Span::new().hours(1))
            .await
            .unwrap();
        let snap = JoinSnapshot {
            members: vec![],
            revoked: HashSet::from(["kicked-peer".into()]),
        };
        let d = auth
            .decide("kicked-peer", "h".into(), &inv.invite_secret, &snap)
            .await;
        assert!(matches!(d, JoinDecision::Denied { reason: "revoked" }));
    }
}
