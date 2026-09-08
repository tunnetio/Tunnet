//! Single-shot Direct join protocol (ALPN [`JOIN_ALPN`]).
//!
//! One request, one response, then close. AUTH is not used. Idempotent retries
//! are handled by [`super::authority::DirectAuthority`].

use std::net::Ipv4Addr;

use anyhow::Context;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::addrplan::validate_peer_cidr;
use super::authority::{DirectAuthority, JoinDecision, JoinSnapshot};
use super::grants::{
    Genesis, NetworkGrant, SignedMemberRecord, validate_member_against_genesis, verify_genesis,
    verify_member_record, verifying_key_from_hex,
};
use super::invite::{InviteCode, decode_invite};
use super::membership::MembershipEntry;

pub const JOIN_ALPN: &[u8] = b"tunnet/direct-join/1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub invite_secret: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinStatus {
    Admitted,
    Pending,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinAdmission {
    pub genesis: Genesis,
    pub ipv4: Ipv4Addr,
    pub doc_ticket: String,
    pub network_grant: NetworkGrant,
    pub member_record: SignedMemberRecord,
    pub content_key: String,
    pub topic_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub status: JoinStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<JoinAdmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<Uuid>,
}

impl JoinResponse {
    pub fn admitted(admission: JoinAdmission) -> Self {
        Self {
            status: JoinStatus::Admitted,
            reason: None,
            admission: Some(admission),
            network_id: None,
        }
    }

    pub fn pending(network_id: Uuid) -> Self {
        Self {
            status: JoinStatus::Pending,
            reason: Some("pending_approval".into()),
            admission: None,
            network_id: Some(network_id),
        }
    }

    pub fn denied(reason: &str) -> Self {
        Self {
            status: JoinStatus::Denied,
            reason: Some(reason.to_string()),
            admission: None,
            network_id: None,
        }
    }
}

async fn write_frame(send: &mut SendStream, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(data).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        anyhow::bail!("join frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        recv.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

/// Verify genesis and reject overlapping local CIDRs before dialing the coordinator.
pub fn preflight_invite(
    invite: &InviteCode,
    existing_plans: &[(Uuid, Ipv4Net)],
    host_nets: &[Ipv4Net],
) -> anyhow::Result<Genesis> {
    let vk = verifying_key_from_hex(&invite.genesis.coordinator_verifying_key)
        .context("invalid coordinator key in invite")?;
    verify_genesis(&vk, &invite.genesis).context("genesis signature invalid")?;
    validate_peer_cidr(&invite.genesis.address_plan.peer_cidr, existing_plans, host_nets)
        .map_err(|e| anyhow::anyhow!("address plan cannot operate locally: {e}"))?;
    Ok(invite.genesis.clone())
}

pub fn decode_and_preflight(
    code: &str,
    existing_plans: &[(Uuid, Ipv4Net)],
    host_nets: &[Ipv4Net],
) -> anyhow::Result<InviteCode> {
    let invite = decode_invite(code)?;
    preflight_invite(&invite, existing_plans, host_nets)?;
    Ok(invite)
}

/// Client: one request / one response / caller closes.
pub async fn run_join_client(
    conn: &Connection,
    invite_secret: &str,
    hostname: &str,
) -> anyhow::Result<JoinResponse> {
    let (mut send, mut recv) = conn.open_bi().await.context("open join stream")?;
    let req = JoinRequest {
        invite_secret: invite_secret.to_string(),
        hostname: hostname.to_string(),
    };
    write_frame(&mut send, &serde_json::to_vec(&req)?).await?;
    send.finish()?;
    let frame = read_frame(&mut recv, 256 * 1024).await?;
    let resp: JoinResponse = serde_json::from_slice(&frame).context("join response json")?;
    Ok(resp)
}

pub fn verify_admission(
    invite: &InviteCode,
    local_endpoint_id: &str,
    hostname: &str,
    admission: &JoinAdmission,
) -> anyhow::Result<()> {
    let vk = verifying_key_from_hex(&invite.genesis.coordinator_verifying_key)?;
    verify_genesis(&vk, &admission.genesis)?;
    if admission.genesis.address_plan != invite.genesis.address_plan {
        anyhow::bail!("genesis address plan mismatch");
    }
    if admission.genesis.network_id != invite.genesis.network_id {
        anyhow::bail!("genesis network mismatch");
    }
    verify_member_record(&vk, &admission.member_record, 0)
        .context("member record signature invalid")?;
    validate_member_against_genesis(&admission.genesis, &admission.member_record)?;
    if admission.member_record.endpoint_id != local_endpoint_id {
        anyhow::bail!("member record endpoint mismatch");
    }
    if admission.member_record.hostname != hostname {
        anyhow::bail!("member record hostname mismatch");
    }
    if admission.member_record.ipv4 != admission.ipv4 {
        anyhow::bail!("membership address mismatch");
    }
    if serde_json::to_value(&admission.member_record.grant)?
        != serde_json::to_value(&admission.network_grant)?
    {
        anyhow::bail!("member record grant mismatch");
    }
    Ok(())
}

pub trait JoinPublisher: Send + Sync {
    fn snapshot(&self) -> JoinSnapshot;
    fn publish(
        &self,
        entry: MembershipEntry,
    ) -> impl std::future::Future<Output = anyhow::Result<JoinAdmission>> + Send;
    fn recover(
        &self,
        entry: &MembershipEntry,
    ) -> impl std::future::Future<Output = anyhow::Result<JoinAdmission>> + Send;
}

/// Server: one request / one response / caller closes.
pub async fn run_join_server<P: JoinPublisher>(
    conn: &Connection,
    authority: &DirectAuthority,
    publisher: &P,
) -> anyhow::Result<JoinResponse> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept join stream")?;
    let remote_id = format!("{}", conn.remote_id());
    let req = match read_join_request(&mut recv).await {
        Ok(req) => req,
        Err(e) => {
            let resp = JoinResponse::denied("bad_request");
            let _ = write_frame(&mut send, &serde_json::to_vec(&resp)?).await;
            return Err(e);
        }
    };
    let resp = process_join_request(&remote_id, req, authority, publisher).await;
    write_frame(&mut send, &serde_json::to_vec(&resp)?).await?;
    send.finish()?;
    let _ = send.stopped().await;
    Ok(resp)
}

pub async fn run_join_server_dispatch<P: JoinPublisher>(
    conn: &Connection,
    networks: &[(DirectAuthority, P)],
) -> anyhow::Result<JoinResponse> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept join stream")?;
    let remote_id = format!("{}", conn.remote_id());
    let req = match read_join_request(&mut recv).await {
        Ok(req) => req,
        Err(e) => {
            let resp = JoinResponse::denied("bad_request");
            let _ = write_frame(&mut send, &serde_json::to_vec(&resp)?).await;
            return Err(e);
        }
    };
    let mut chosen = None;
    for (i, (authority, _)) in networks.iter().enumerate() {
        if authority.has_invite_secret(&req.invite_secret).await {
            chosen = Some(i);
            break;
        }
    }
    let Some(i) = chosen else {
        let resp = JoinResponse::denied("invalid_or_used_invite");
        write_frame(&mut send, &serde_json::to_vec(&resp)?).await?;
        send.finish()?;
        return Ok(resp);
    };
    let (authority, publisher) = &networks[i];
    let resp = process_join_request(&remote_id, req, authority, publisher).await;
    write_frame(&mut send, &serde_json::to_vec(&resp)?).await?;
    send.finish()?;
    let _ = send.stopped().await;
    Ok(resp)
}

async fn read_join_request(recv: &mut RecvStream) -> anyhow::Result<JoinRequest> {
    let frame = read_frame(recv, 64 * 1024).await?;
    serde_json::from_slice(&frame).context("join request json")
}

async fn process_join_request<P: JoinPublisher>(
    remote_id: &str,
    req: JoinRequest,
    authority: &DirectAuthority,
    publisher: &P,
) -> JoinResponse {
    let hostname = if req.hostname.trim().is_empty() {
        "peer".into()
    } else {
        req.hostname
    };
    let snap = publisher.snapshot();
    let decision = authority
        .decide(remote_id, hostname, &req.invite_secret, &snap)
        .await;
    match decision {
        JoinDecision::Denied { reason } => JoinResponse::denied(reason),
        JoinDecision::Pending => JoinResponse::pending(authority.network_id),
        JoinDecision::Admit { entry, recover } => {
            let published = if recover {
                match publisher.recover(&entry).await {
                    Ok(admission) => Ok(admission),
                    Err(_) => publisher.publish(entry.clone()).await,
                }
            } else {
                publisher.publish(entry.clone()).await
            };
            match published {
                Ok(admission) => {
                    if let Err(e) = authority.confirm(&entry.endpoint_id, entry.ipv4).await {
                        tracing::warn!(?e, "join confirm persist failed");
                    }
                    JoinResponse::admitted(admission)
                }
                Err(e) => {
                    tracing::warn!(?e, "join membership publish failed");
                    JoinResponse::denied("membership_failed")
                }
            }
        }
    }
}
