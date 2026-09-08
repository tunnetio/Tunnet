//! Protocol-level Direct join tests using two real iroh endpoints.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use iroh::Endpoint;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use parking_lot::Mutex;
use tunnet_core::direct::addrplan::select_peer_cidr;
use tunnet_core::direct::grants::{
    GENESIS_SCHEMA_VERSION, generate_coordinator_keypair, sign_genesis, sign_grant,
    sign_member_record, verify_grant,
};
use tunnet_core::direct::{
    AUTH_ALPN, AuthCache, DirectAuthority, JOIN_ALPN, JoinAdmission, JoinPublisher, JoinSnapshot,
    JoinStatus, MEMBER_SCHEMA_VERSION, MemberRole, MembershipEntry, NetworkGrant,
    decode_and_preflight, grant_expiry, preflight_invite, run_auth_client, run_auth_server,
    run_join_client, verify_admission,
};
use tunnet_core::direct::{AuthServerContext, SharedAuthServerContext};
use tunnet_core::state::StatePaths;
use uuid::Uuid;

#[derive(Clone)]
struct MemNet {
    inner: Arc<Mutex<MemInner>>,
    auth: AuthCache,
}

struct MemInner {
    members: HashMap<String, MembershipEntry>,
    revoked: HashSet<String>,
    genesis: tunnet_core::direct::Genesis,
    sk: ed25519_dalek::SigningKey,
    content_key: String,
    topic_hash: String,
    fail_publish: bool,
}

impl MemNet {
    fn new(
        genesis: tunnet_core::direct::Genesis,
        sk: ed25519_dalek::SigningKey,
        auth: AuthCache,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemInner {
                members: HashMap::new(),
                revoked: HashSet::new(),
                genesis,
                sk,
                content_key: hex::encode([9u8; 32]),
                topic_hash: "ab".repeat(32),
                fail_publish: false,
            })),
            auth,
        }
    }

    fn set_fail_publish(&self, fail: bool) {
        self.inner.lock().fail_publish = fail;
    }

    fn revoke(&self, endpoint_id: &str) {
        let mut g = self.inner.lock();
        g.revoked.insert(endpoint_id.to_string());
        g.members.remove(endpoint_id);
        self.auth.remove(endpoint_id);
    }

    fn member_count(&self) -> usize {
        self.inner.lock().members.len()
    }
}

impl JoinPublisher for MemNet {
    fn snapshot(&self) -> JoinSnapshot {
        let g = self.inner.lock();
        JoinSnapshot {
            members: g.members.values().cloned().collect(),
            revoked: g.revoked.clone(),
        }
    }

    async fn publish(&self, entry: MembershipEntry) -> anyhow::Result<JoinAdmission> {
        let mut g = self.inner.lock();
        if g.fail_publish {
            anyhow::bail!("forced membership failure");
        }
        let now = jiff::Timestamp::now();
        let grant = sign_grant(
            &g.sk,
            NetworkGrant {
                network_id: g.genesis.network_id,
                endpoint_id: entry.endpoint_id.clone(),
                role: MemberRole::Member,
                network_epoch: 0,
                issued_at: now,
                expires_at: grant_expiry(now)?,
                content_key: g.content_key.clone(),
                sig: String::new(),
            },
        )?;
        let record = sign_member_record(
            &g.sk,
            tunnet_core::direct::SignedMemberRecord {
                schema_version: MEMBER_SCHEMA_VERSION,
                network_id: g.genesis.network_id,
                endpoint_id: entry.endpoint_id.clone(),
                hostname: entry.hostname.clone(),
                ipv4: entry.ipv4,
                tags: vec![],
                status: "active".into(),
                ssh_host_key: None,
                sequence: 1,
                joined_at: entry.joined_at,
                grant: grant.clone(),
                endpoint_sig: String::new(),
                coordinator: false,
            },
        )?;
        g.members.insert(entry.endpoint_id.clone(), entry.clone());
        self.auth
            .insert(entry.endpoint_id.clone(), g.genesis.network_id);
        Ok(JoinAdmission {
            genesis: g.genesis.clone(),
            ipv4: entry.ipv4,
            doc_ticket: "ticket".into(),
            network_grant: grant,
            member_record: record,
            content_key: g.content_key.clone(),
            topic_hash: g.topic_hash.clone(),
        })
    }

    async fn recover(&self, entry: &MembershipEntry) -> anyhow::Result<JoinAdmission> {
        if !self.inner.lock().members.contains_key(&entry.endpoint_id) {
            anyhow::bail!("not published");
        }
        self.publish(entry.clone()).await
    }
}

#[derive(Clone)]
struct JoinHandler {
    authority: DirectAuthority,
    net: MemNet,
    auth: AuthCache,
}

impl std::fmt::Debug for JoinHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandler").finish()
    }
}

impl ProtocolHandler for JoinHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match tunnet_core::direct::run_join_server(&conn, &self.authority, &self.net).await {
            Ok(resp) if resp.status == JoinStatus::Admitted => {
                for m in self.net.snapshot().members {
                    self.auth.insert(m.endpoint_id, self.authority.network_id);
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(?e, "join server"),
        }
        conn.close(0u32.into(), b"join_done");
        Ok(())
    }
}

#[derive(Clone)]
struct AuthHandler {
    ctx: SharedAuthServerContext,
    auth: AuthCache,
    self_id: String,
}

impl std::fmt::Debug for AuthHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthHandler").finish()
    }
}

impl ProtocolHandler for AuthHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match run_auth_server(&conn, &self.ctx, &self.self_id, &self.auth).await {
            Ok(_) => {}
            Err(_) => conn.close(401u32.into(), b"auth_failed"),
        }
        Ok(())
    }
}

struct Harness {
    _tmp: tempfile::TempDir,
    authority: DirectAuthority,
    net: MemNet,
    auth: AuthCache,
    coord: Endpoint,
    _router: Router,
    vk: ed25519_dalek::VerifyingKey,
    disco: MemoryLookup,
}

async fn harness(open: bool) -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths {
        dir: tmp.path().to_path_buf(),
    };
    let (sk, vk) = generate_coordinator_keypair();
    let disco = MemoryLookup::new();
    let coord = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .address_lookup(disco.clone())
        .alpns(vec![JOIN_ALPN.to_vec(), AUTH_ALPN.to_vec()])
        .bind()
        .await
        .expect("coord bind");
    disco.add_endpoint_info(coord.addr());
    let cidr = select_peer_cidr(&[], &[]).unwrap();
    let genesis = sign_genesis(
        &sk,
        tunnet_core::direct::Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: Uuid::new_v4(),
            network_name: "lab".into(),
            coordinator_endpoint_id: format!("{}", coord.id()),
            coordinator_verifying_key: hex::encode(vk.to_bytes()),
            address_plan: cidr,
            created_at: jiff::Timestamp::now(),
            sig: String::new(),
        },
    )
    .unwrap();
    let authority = DirectAuthority::load(
        &paths,
        genesis.network_id,
        open,
        genesis.clone(),
        "ab".repeat(32),
    )
    .unwrap();
    let auth = AuthCache::new();
    let net = MemNet::new(genesis, sk, auth.clone());
    let vk_for_ctx = vk;
    let net_for_ctx = net.clone();
    let ctx = Arc::new(AuthServerContext {
        resolve_coord_vk: Arc::new(move |_| Some(vk_for_ctx)),
        resolve_min_epoch: Arc::new(|_| 0),
        is_revoked: Arc::new({
            let net = net_for_ctx.clone();
            move |_, eid| net.snapshot().revoked.contains(eid)
        }),
    });
    let router = Router::builder(coord.clone())
        .accept(
            JOIN_ALPN,
            JoinHandler {
                authority: authority.clone(),
                net: net.clone(),
                auth: auth.clone(),
            },
        )
        .accept(
            AUTH_ALPN,
            AuthHandler {
                ctx,
                auth: auth.clone(),
                self_id: format!("{}", coord.id()),
            },
        )
        .spawn();
    Harness {
        _tmp: tmp,
        authority,
        net,
        auth,
        coord,
        _router: router,
        vk,
        disco,
    }
}

async fn peer_endpoint(disco: &MemoryLookup) -> Endpoint {
    let ep = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .address_lookup(disco.clone())
        .alpns(vec![JOIN_ALPN.to_vec(), AUTH_ALPN.to_vec()])
        .bind()
        .await
        .expect("peer bind");
    disco.add_endpoint_info(ep.addr());
    ep
}

async fn join_once(
    peer: &Endpoint,
    coord: &Endpoint,
    secret: &str,
    hostname: &str,
) -> tunnet_core::direct::JoinResponse {
    let conn = peer
        .connect(coord.id(), JOIN_ALPN)
        .await
        .expect("dial join");
    let resp = run_join_client(&conn, secret, hostname)
        .await
        .expect("join rpc");
    conn.close(0u32.into(), b"done");
    resp
}

#[tokio::test]
async fn one_time_join_then_same_endpoint_retry() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let r1 = join_once(&a, &h.coord, &invite.invite_secret, "alpha").await;
    assert_eq!(r1.status, JoinStatus::Admitted);
    let adm = r1.admission.unwrap();
    verify_admission(&invite, &format!("{}", a.id()), "alpha", &adm).unwrap();
    assert_eq!(h.net.member_count(), 1);
    assert!(h.auth.contains(&format!("{}", a.id())));

    let r2 = join_once(&a, &h.coord, &invite.invite_secret, "alpha").await;
    assert_eq!(r2.status, JoinStatus::Admitted);
    assert_eq!(r2.admission.unwrap().ipv4, adm.ipv4);
    assert_eq!(h.net.member_count(), 1);
}

#[tokio::test]
async fn one_time_replay_other_endpoint_denied() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let b = peer_endpoint(&h.disco).await;
    assert_eq!(
        join_once(&a, &h.coord, &invite.invite_secret, "a")
            .await
            .status,
        JoinStatus::Admitted
    );
    let r = join_once(&b, &h.coord, &invite.invite_secret, "b").await;
    assert_eq!(r.status, JoinStatus::Denied);
    assert_eq!(r.reason.as_deref(), Some("invite_claimed"));
}

#[tokio::test]
async fn expired_and_revoked_invite() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            true,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    h.authority
        .revoke_invite_secret(&invite.invite_secret)
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let r = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    assert_eq!(r.status, JoinStatus::Denied);
    assert_eq!(r.reason.as_deref(), Some("invite_revoked"));
}

#[tokio::test]
async fn local_cidr_conflict_before_admission() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            true,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let host = vec![invite.genesis.address_plan.peer_cidr];
    let err = preflight_invite(&invite, &[], &host).unwrap_err();
    assert!(
        err.to_string()
            .contains("address plan cannot operate locally")
    );
    assert_eq!(h.net.member_count(), 0);
}

#[tokio::test]
async fn response_loss_retry_recovers_same_ip() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let r1 = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    let ip = r1.admission.unwrap().ipv4;
    // Simulate lost response: client retries without local state.
    let r2 = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    assert_eq!(r2.status, JoinStatus::Admitted);
    assert_eq!(r2.admission.unwrap().ipv4, ip);
}

#[tokio::test]
async fn pending_approval_then_retry() {
    let h = harness(false).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let r1 = join_once(&a, &h.coord, &invite.invite_secret, "wait").await;
    assert_eq!(r1.status, JoinStatus::Pending);
    assert_eq!(h.net.member_count(), 0);
    h.authority.approve(&format!("{}", a.id())).await.unwrap();
    let r2 = join_once(&a, &h.coord, &invite.invite_secret, "wait").await;
    assert_eq!(r2.status, JoinStatus::Admitted);
}

#[tokio::test]
async fn revoked_peer_cannot_rejoin_or_auth() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            true,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    let r1 = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    let grant = r1.admission.unwrap().network_grant;
    h.net.revoke(&format!("{}", a.id()));
    let invite2 = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            true,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let r2 = join_once(&a, &h.coord, &invite2.invite_secret, "a").await;
    assert_eq!(r2.status, JoinStatus::Denied);
    assert_eq!(r2.reason.as_deref(), Some("revoked"));

    let conn = a.connect(h.coord.id(), AUTH_ALPN).await.expect("dial auth");
    let err = run_auth_client(&conn, grant, &format!("{}", a.id())).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn membership_publish_failure_then_retry() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let a = peer_endpoint(&h.disco).await;
    h.net.set_fail_publish(true);
    let r1 = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    assert_eq!(r1.status, JoinStatus::Denied);
    assert_eq!(r1.reason.as_deref(), Some("membership_failed"));
    h.net.set_fail_publish(false);
    let r2 = join_once(&a, &h.coord, &invite.invite_secret, "a").await;
    assert_eq!(r2.status, JoinStatus::Admitted);
    assert_eq!(h.net.member_count(), 1);
}

#[tokio::test]
async fn create_invite_join_verified_membership_and_auth() {
    let h = harness(true).await;
    let invite = h
        .authority
        .issue_invite(
            &format!("{}", h.coord.id()),
            false,
            jiff::Span::new().hours(24),
        )
        .await
        .unwrap();
    let encoded = tunnet_core::direct::encode_invite(&invite).unwrap();
    let decoded = decode_and_preflight(&encoded, &[], &[]).unwrap();
    let a = peer_endpoint(&h.disco).await;
    let resp = join_once(&a, &h.coord, &decoded.invite_secret, "node").await;
    assert_eq!(resp.status, JoinStatus::Admitted);
    let adm = resp.admission.unwrap();
    verify_admission(&decoded, &format!("{}", a.id()), "node", &adm).unwrap();
    verify_grant(&h.vk, &adm.network_grant, 0).unwrap();
    assert!(h.auth.contains(&format!("{}", a.id())));

    let conn = a
        .connect(h.coord.id(), AUTH_ALPN)
        .await
        .expect("dial grant auth");
    run_auth_client(&conn, adm.network_grant, &format!("{}", a.id()))
        .await
        .expect("grant auth");
}

#[tokio::test]
async fn decode_rejects_unsigned_genesis_in_invite() {
    let (sk, vk) = generate_coordinator_keypair();
    let cidr = select_peer_cidr(&[], &[]).unwrap();
    let genesis = sign_genesis(
        &sk,
        tunnet_core::direct::Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: Uuid::nil(),
            network_name: "x".into(),
            coordinator_endpoint_id: "aa".repeat(32),
            coordinator_verifying_key: hex::encode(vk.to_bytes()),
            address_plan: cidr,
            created_at: jiff::Timestamp::now(),
            sig: String::new(),
        },
    )
    .unwrap();
    let mut bad = genesis.clone();
    bad.sig = "00".repeat(64);
    let invite = tunnet_core::direct::InviteCode {
        genesis: bad,
        invite_secret: hex::encode([1u8; 32]),
        expires_at: jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    };
    let code = tunnet_core::direct::encode_invite(&invite).unwrap();
    assert!(tunnet_core::direct::decode_invite(&code).is_err());
    let _ = sk;
    let _ = Ipv4Addr::UNSPECIFIED;
}
