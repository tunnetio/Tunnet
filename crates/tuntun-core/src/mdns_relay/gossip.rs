use anyhow::Context;
use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use iroh_gossip::{TopicId, api::Event};
use tokio::sync::mpsc;

use super::types::ServiceRecord;
use crate::routing::RoutingTable;

pub async fn run_gossip(
    gossip: Gossip,
    topic_hex: String,
    bootstrap: Vec<EndpointId>,
    routes: RoutingTable,
    self_endpoint_id: String,
    mut outbound: mpsc::UnboundedReceiver<ServiceRecord>,
    inbound: mpsc::UnboundedSender<ServiceRecord>,
) -> anyhow::Result<()> {
    let topic_bytes = hex::decode(&topic_hex).context("mdns-relay topic hex")?;
    let arr: [u8; 32] = topic_bytes
        .as_slice()
        .try_into()
        .context("mdns-relay topic must be 32 bytes")?;
    let topic = TopicId::from_bytes(arr);

    let (sender, mut receiver) = gossip.subscribe(topic, bootstrap).await?.split();
    tracing::info!(%topic_hex, "mDNS service-relay gossip subscribed");

    let recv = tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    let Ok(record) = serde_json::from_slice::<ServiceRecord>(&msg.content) else {
                        continue;
                    };
                    if record.origin_endpoint_id == self_endpoint_id {
                        continue;
                    }
                    if routes.lookup_endpoint(&record.origin_endpoint_id).is_none() {
                        tracing::debug!(
                            peer = %record.origin_endpoint_id,
                            "ignore ServiceRecord from unknown peer"
                        );
                        continue;
                    }
                    tracing::debug!(
                        fullname = %record.fullname,
                        peer = %record.origin_peer_ip,
                        event = ?record.event_type,
                        "ServiceRecord received"
                    );
                    let _ = inbound.send(record);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(?e, "mdns-relay gossip event error");
                    break;
                }
            }
        }
    });

    let publish = tokio::spawn(async move {
        let _gossip = gossip;
        while let Some(record) = outbound.recv().await {
            let Ok(bytes) = serde_json::to_vec(&record) else {
                continue;
            };
            if let Err(e) = sender.broadcast(bytes.into()).await {
                tracing::debug!(?e, "mdns-relay gossip broadcast skipped");
                break;
            }
        }
    });

    tokio::select! {
        _ = recv => tracing::debug!("mdns-relay gossip receiver exited"),
        _ = publish => tracing::debug!("mdns-relay gossip publisher exited"),
    }
    Ok(())
}
