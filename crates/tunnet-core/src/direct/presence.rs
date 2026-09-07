//! Gossip presence beacons with TTL and endpoint identity signatures.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use iroh_gossip::{TopicId, api::Event};
use jiff::{SignedDuration, Timestamp};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PRESENCE_TTL: SignedDuration = SignedDuration::from_secs(90);
pub const PRESENCE_PUBLISH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceBeacon {
    pub network_id: Uuid,
    pub endpoint_id: String,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_key: Option<String>,
    pub agent_version: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub issued_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
    pub sig: String,
}

#[derive(Clone, Default)]
pub struct PresenceTable {
    peers: Arc<Mutex<HashMap<String, PresenceBeacon>>>,
}

impl PresenceTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, beacon: PresenceBeacon) {
        self.peers.lock().insert(beacon.endpoint_id.clone(), beacon);
    }

    pub fn remove_expired(&self, now: Timestamp) {
        self.peers.lock().retain(|_, b| b.expires_at > now);
    }

    pub fn is_online(&self, endpoint_id: &str, now: Timestamp) -> bool {
        self.peers
            .lock()
            .get(endpoint_id)
            .is_some_and(|b| b.expires_at > now)
    }

    /// `None` = never seen (unknown), `Some(true)` = live beacon, `Some(false)` = expired.
    pub fn presence_status(&self, endpoint_id: &str, now: Timestamp) -> Option<bool> {
        let peers = self.peers.lock();
        let beacon = peers.get(endpoint_id)?;
        Some(beacon.expires_at > now)
    }

    pub fn last_seen(&self, endpoint_id: &str, now: Timestamp) -> Option<SignedDuration> {
        let beacon = self.peers.lock().get(endpoint_id).cloned()?;
        if beacon.expires_at <= now {
            return None;
        }
        Some(now.duration_since(beacon.issued_at))
    }

    pub fn snapshot(&self) -> HashMap<String, PresenceBeacon> {
        self.peers.lock().clone()
    }
}

#[derive(Clone)]
pub struct PresenceConfig {
    pub gossip: Gossip,
    pub network_id: Uuid,
    pub signing_key: SigningKey,
    pub self_endpoint_id: String,
    pub hostname: String,
    pub mesh_ip: Option<String>,
    pub ssh_host_key: Option<String>,
    pub agent_version: String,
    pub bootstrap: Vec<EndpointId>,
    pub state_dir: Option<PathBuf>,
    pub dns_suffix: Option<String>,
}

pub struct PresenceHandle {
    pub table: Arc<PresenceTable>,
}

fn sign_bytes(sk: &SigningKey, payload: &[u8]) -> String {
    hex::encode(sk.sign(payload).to_bytes())
}

fn verify_sig(vk: &VerifyingKey, payload: &[u8], sig_hex: &str) -> anyhow::Result<()> {
    let sig_bytes = hex::decode(sig_hex.trim()).context("invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(payload, &sig)
        .map_err(|_| anyhow::anyhow!("invalid signature"))
}

#[derive(Serialize)]
struct BeaconSignPayload<'a> {
    network_id: Uuid,
    endpoint_id: &'a str,
    hostname: &'a str,
    mesh_ip: Option<&'a str>,
    ssh_host_key: Option<&'a str>,
    agent_version: &'a str,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    issued_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    expires_at: Timestamp,
}

fn beacon_sign_payload(beacon: &PresenceBeacon) -> anyhow::Result<Vec<u8>> {
    let payload = BeaconSignPayload {
        network_id: beacon.network_id,
        endpoint_id: &beacon.endpoint_id,
        hostname: &beacon.hostname,
        mesh_ip: beacon.mesh_ip.as_deref(),
        ssh_host_key: beacon.ssh_host_key.as_deref(),
        agent_version: &beacon.agent_version,
        issued_at: beacon.issued_at,
        expires_at: beacon.expires_at,
    };
    Ok(serde_json::to_vec(&payload)?)
}

pub fn sign_beacon(sk: &SigningKey, mut beacon: PresenceBeacon) -> anyhow::Result<PresenceBeacon> {
    let payload = beacon_sign_payload(&beacon)?;
    beacon.sig = sign_bytes(sk, &payload);
    Ok(beacon)
}

pub fn verify_beacon(beacon: &PresenceBeacon, now: Timestamp) -> anyhow::Result<VerifyingKey> {
    if beacon.expires_at < now {
        bail!("presence beacon expired");
    }
    let vk = super::grants::verifying_key_from_hex(&beacon.endpoint_id)
        .context("presence endpoint_id must be a verifying key")?;
    let payload = beacon_sign_payload(beacon)?;
    verify_sig(&vk, &payload, &beacon.sig)?;
    Ok(vk)
}

pub fn build_beacon(
    network_id: Uuid,
    signing_key: &SigningKey,
    hostname: &str,
    mesh_ip: Option<String>,
    ssh_host_key: Option<String>,
    agent_version: &str,
    now: Timestamp,
) -> anyhow::Result<PresenceBeacon> {
    let endpoint_id = hex::encode(signing_key.verifying_key().to_bytes());
    let beacon = PresenceBeacon {
        network_id,
        endpoint_id,
        hostname: hostname.to_string(),
        mesh_ip,
        ssh_host_key,
        agent_version: agent_version.to_string(),
        issued_at: now,
        expires_at: now + PRESENCE_TTL,
        sig: String::new(),
    };
    sign_beacon(signing_key, beacon)
}

pub async fn spawn_presence(cfg: PresenceConfig) -> anyhow::Result<PresenceHandle> {
    let topic_hex = tunnet_common::network_topic_hex(&cfg.network_id);
    let topic_bytes = hex::decode(&topic_hex).context("presence topic hex")?;
    let arr: [u8; 32] = topic_bytes
        .as_slice()
        .try_into()
        .context("presence topic must be 32 bytes")?;
    let topic = TopicId::from_bytes(arr);

    let table = Arc::new(PresenceTable::new());
    let (sender, mut receiver) = cfg.gossip.subscribe(topic, cfg.bootstrap).await?.split();

    let recv_table = table.clone();
    let recv_state_dir = cfg.state_dir.clone();
    let recv_suffix = cfg.dns_suffix.clone();
    tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    let Ok(beacon) = serde_json::from_slice::<PresenceBeacon>(&msg.content) else {
                        continue;
                    };
                    let now = Timestamp::now();
                    if verify_beacon(&beacon, now).is_err() {
                        tracing::debug!(peer = %beacon.endpoint_id, "ignored invalid presence beacon");
                        continue;
                    }
                    tracing::debug!(
                        peer = %beacon.endpoint_id,
                        host = %beacon.hostname,
                        "gossip presence"
                    );
                    recv_table.upsert(beacon.clone());
                    if let (Some(dir), Some(suffix)) =
                        (recv_state_dir.as_ref(), recv_suffix.as_deref())
                        && let Some(key) = beacon.ssh_host_key.as_deref().filter(|k| !k.is_empty())
                    {
                        let fqdn = format!("{}.{}", beacon.hostname, suffix);
                        let mut hosts = vec![beacon.hostname.as_str(), fqdn.as_str()];
                        if let Some(ip) = beacon.mesh_ip.as_deref() {
                            hosts.insert(0, ip);
                        }
                        if let Err(e) =
                            crate::known_hosts::upsert_known_hosts_entry(dir, &hosts, key)
                        {
                            tracing::debug!(?e, "presence known_hosts upsert skipped");
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(?e, "presence gossip event error");
                    break;
                }
            }
        }
    });

    let publish_table = table.clone();
    let signing_key = cfg.signing_key;
    let self_endpoint_id = cfg.self_endpoint_id;
    let hostname = cfg.hostname;
    let mesh_ip = cfg.mesh_ip;
    let ssh_host_key = cfg.ssh_host_key;
    let agent_version = cfg.agent_version;
    let network_id = cfg.network_id;
    let _gossip = cfg.gossip;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PRESENCE_PUBLISH_INTERVAL);
        loop {
            ticker.tick().await;
            let now = Timestamp::now();
            publish_table.remove_expired(now);
            let Ok(beacon) = build_beacon(
                network_id,
                &signing_key,
                &hostname,
                mesh_ip.clone(),
                ssh_host_key.clone(),
                &agent_version,
                now,
            ) else {
                continue;
            };
            debug_assert_eq!(beacon.endpoint_id, self_endpoint_id);
            let Ok(bytes) = serde_json::to_vec(&beacon) else {
                continue;
            };
            if let Err(e) = sender.broadcast(bytes.into()).await {
                tracing::debug!(?e, "presence broadcast skipped");
                break;
            }
        }
    });

    Ok(PresenceHandle { table })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> SigningKey {
        SigningKey::generate(&mut rand::rng())
    }

    #[test]
    fn presence_sign_verify_roundtrip() {
        let sk = sample_key();
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let beacon = build_beacon(
            Uuid::new_v4(),
            &sk,
            "host-a",
            Some("10.21.0.2".into()),
            None,
            "0.1.0",
            now,
        )
        .unwrap();
        assert!(verify_beacon(&beacon, now).is_ok());
    }

    #[test]
    fn presence_expiry_rejected() {
        let sk = sample_key();
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let beacon = build_beacon(Uuid::new_v4(), &sk, "host-a", None, None, "0.1.0", now).unwrap();
        assert!(verify_beacon(&beacon, now + PRESENCE_TTL + SignedDuration::from_secs(1)).is_err());
    }
}
