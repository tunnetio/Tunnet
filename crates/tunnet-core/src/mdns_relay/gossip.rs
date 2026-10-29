use anyhow::Context;
use ed25519_dalek::Signer;
use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_gossip::{TopicId, api::Event, net::Gossip};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

use super::types::ServiceRecord;
use crate::forward::{ForwardingSnapshot, ForwardingStore};
use crate::identity::AgentIdentity;

const MAX_RECORD_BYTES: usize = 16 * 1024;
const SIGNATURE_CONTEXT: &[u8] = b"Tunnet service record\0";

#[derive(Serialize, Deserialize)]
struct RecordClaim {
    network: Uuid,
    record: ServiceRecord,
}

#[derive(Serialize, Deserialize)]
struct SignedRecord {
    payload: String,
    signature: String,
}

fn signature_input(payload: &str) -> Vec<u8> {
    [SIGNATURE_CONTEXT, payload.as_bytes()].concat()
}

fn encode_record(
    identity: &AgentIdentity,
    network: Uuid,
    record: ServiceRecord,
) -> anyhow::Result<Vec<u8>> {
    let payload = serde_json::to_string(&RecordClaim { network, record })?;
    let signature = identity.signing_key.sign(&signature_input(&payload));
    let bytes = serde_json::to_vec(&SignedRecord {
        payload,
        signature: hex::encode(signature.to_bytes()),
    })?;
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "service record exceeds limit"
    );
    Ok(bytes)
}

fn decode_record(bytes: &[u8], network: Uuid) -> anyhow::Result<ServiceRecord> {
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "service record exceeds limit"
    );
    let signed: SignedRecord = serde_json::from_slice(bytes)?;
    let claim: RecordClaim = serde_json::from_str(&signed.payload)?;
    let now = jiff::Timestamp::now().as_second();
    anyhow::ensure!(
        claim.network == network
            && claim.record.valid_until.as_second() > now
            && claim.record.valid_until.as_second() <= now + 300,
        "invalid service record authority"
    );
    let origin: EndpointId = claim.record.origin_endpoint_id.parse()?;
    let signature: [u8; 64] = hex::decode(signed.signature)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid service signature length"))?;
    let signature = iroh::Signature::from_bytes(&signature);
    origin.verify(&signature_input(&signed.payload), &signature)?;
    Ok(claim.record)
}

pub(super) fn record_authorized(
    snapshot: &ForwardingSnapshot,
    network: Uuid,
    record: &ServiceRecord,
) -> bool {
    let Ok(origin) = record.origin_endpoint_id.parse() else {
        return false;
    };
    snapshot.allows_network(network, origin)
        && snapshot
            .binding(network, origin)
            .is_some_and(|binding| binding.ip == record.origin_peer_ip)
        && snapshot.address_isolated(network, record.origin_peer_ip)
}

pub async fn run_gossip(
    gossip: Gossip,
    network: Uuid,
    bootstrap: Vec<EndpointId>,
    forwarding: ForwardingStore,
    identity: AgentIdentity,
    mut outbound: mpsc::Receiver<ServiceRecord>,
    inbound: mpsc::Sender<ServiceRecord>,
) -> anyhow::Result<()> {
    let topic_hex = tunnet_common::mdns_relay_topic_hex(&network);
    let topic_bytes = hex::decode(&topic_hex).context("mdns-relay topic hex")?;
    let arr: [u8; 32] = topic_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid mDNS topic"))?;
    let (sender, mut receiver) = gossip
        .subscribe(TopicId::from_bytes(arr), bootstrap)
        .await?
        .split();
    let receive_store = forwarding.clone();
    let self_endpoint_id = identity.endpoint_id_hex();
    let recv = tokio::spawn(async move {
        while let Some(event) = receiver.next().await {
            let Ok(Event::Received(message)) = event else {
                continue;
            };
            let Ok(record) = decode_record(&message.content, network) else {
                continue;
            };
            if record.origin_endpoint_id == self_endpoint_id {
                continue;
            }
            let allowed = {
                let gate = receive_store.authorization_gate();
                let _guard = gate.read();
                let snapshot = receive_store.load();
                snapshot.allows_network(network, message.delivered_from)
                    && record_authorized(&snapshot, network, &record)
            };
            if allowed && inbound.send(record).await.is_err() {
                break;
            }
        }
    });
    // Signature identity is immutable; the publication authority remains live.
    let publish_identity = identity;
    let publish = tokio::spawn(async move {
        let _gossip = gossip;
        while let Some(record) = outbound.recv().await {
            let allowed = {
                let snapshot = forwarding.load();
                snapshot.local_ip(network) == Some(record.origin_peer_ip)
                    && snapshot.self_id.endpoint_hex == record.origin_endpoint_id
                    && snapshot.policy_for(network).is_some()
            };
            if !allowed {
                continue;
            }
            let Ok(bytes) = encode_record(&publish_identity, network, record) else {
                continue;
            };
            if sender.broadcast(bytes.into()).await.is_err() {
                break;
            }
        }
    });
    let mut recv = AbortOnDropHandle::new(recv);
    let mut publish = AbortOnDropHandle::new(publish);
    tokio::select! { _ = &mut recv => {}, _ = &mut publish => {} }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_signatures_bind_network_origin_contents_and_deadline() {
        let identity = AgentIdentity::from_bytes([21; 32]);
        let network = Uuid::nil();
        let record = ServiceRecord {
            service_type: "_printer._tcp.local.".into(),
            instance_name: "printer".into(),
            fullname: "printer._printer._tcp.local.".into(),
            origin_peer_ip: "100.64.0.2".parse().unwrap(),
            origin_endpoint_id: identity.endpoint_id_hex(),
            lan_ip: "192.168.1.10".parse().unwrap(),
            port: 631,
            txt_records: Default::default(),
            valid_until: jiff::Timestamp::now() + jiff::SignedDuration::from_secs(60),
            event_type: super::super::types::EventType::Added,
        };
        let signed = encode_record(&identity, network, record.clone()).unwrap();
        assert_eq!(decode_record(&signed, network).unwrap().port, 631);
        assert!(decode_record(&signed, Uuid::from_u128(1)).is_err());
        let mut envelope: SignedRecord = serde_json::from_slice(&signed).unwrap();
        let mut claim: RecordClaim = serde_json::from_str(&envelope.payload).unwrap();
        claim.record.port = 22;
        envelope.payload = serde_json::to_string(&claim).unwrap();
        assert!(decode_record(&serde_json::to_vec(&envelope).unwrap(), network).is_err());
        let mut forged = record.clone();
        forged.origin_endpoint_id = AgentIdentity::from_bytes([22; 32]).endpoint_id_hex();
        assert!(
            decode_record(&encode_record(&identity, network, forged).unwrap(), network).is_err()
        );
        let mut expired = record;
        expired.valid_until = jiff::Timestamp::now() - jiff::SignedDuration::from_secs(1);
        assert!(
            decode_record(
                &encode_record(&identity, network, expired).unwrap(),
                network
            )
            .is_err()
        );
    }
}
