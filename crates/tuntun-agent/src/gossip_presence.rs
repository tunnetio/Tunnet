use std::time::Duration;

use anyhow::Context;
use iroh::{Endpoint, EndpointId};
use iroh_gossip::net::Gossip;
use iroh_gossip::{TopicId, api::Event};
use serde::{Deserialize, Serialize};

use futures_util::StreamExt;

#[derive(Serialize, Deserialize)]
struct Beacon {
    endpoint_id: String,
    hostname: String,
    agent_version: String,
    ts: i64,
}

pub async fn spawn(
    endpoint: Endpoint,
    gossip: Gossip,
    topic_hex: String,
    bootstrap: Vec<EndpointId>,
    self_hostname: String,
) -> anyhow::Result<()> {
    let topic_bytes = hex::decode(&topic_hex).context("topic hex")?;
    let arr: [u8; 32] = topic_bytes
        .as_slice()
        .try_into()
        .context("topic must be 32 bytes")?;
    let topic = TopicId::from_bytes(arr);

    let self_id = format!("{}", endpoint.id());
    let (sender, mut receiver) = gossip.subscribe(topic, bootstrap).await?.split();

    let recv = tokio::spawn(async move {
        while let Some(ev) = receiver.next().await {
            match ev {
                Ok(Event::Received(msg)) => {
                    if let Ok(beacon) = serde_json::from_slice::<Beacon>(&msg.content) {
                        tracing::debug!(
                            peer = %beacon.endpoint_id,
                            host = %beacon.hostname,
                            "gossip presence"
                        );
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(?e, "gossip event error");
                    break;
                }
            }
        }
    });

    let publisher_id = self_id.clone();
    let publish = tokio::spawn(async move {
        // Hold Gossip for the publisher lifetime.
        let _gossip = gossip;
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let b = Beacon {
                endpoint_id: publisher_id.clone(),
                hostname: self_hostname.clone(),
                agent_version: env!("CARGO_PKG_VERSION").into(),
                ts: chrono::Utc::now().timestamp(),
            };
            let Ok(bytes) = serde_json::to_vec(&b) else {
                continue;
            };
            if let Err(e) = sender.broadcast(bytes.into()).await {
                tracing::debug!(?e, "gossip broadcast skipped");
                break;
            }
        }
    });

    tokio::select! {
        _ = recv => tracing::debug!("gossip receiver exited"),
        _ = publish => tracing::debug!("gossip publisher exited"),
    }
    Ok(())
}
