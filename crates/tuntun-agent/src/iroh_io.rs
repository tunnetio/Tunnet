//! iroh connection pool + datagram send helper.

use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId};
use tokio::sync::Mutex;

use tuntun_common::TUNNEL_ALPN;

#[derive(Clone)]
pub struct ConnPool {
    endpoint: Endpoint,
    entries: Arc<DashMap<EndpointId, Arc<Mutex<Option<Connection>>>>>,
}

impl ConnPool {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            entries: Arc::new(DashMap::new()),
        }
    }

    pub async fn get(&self, peer: EndpointId) -> anyhow::Result<Connection> {
        let slot = self
            .entries
            .entry(peer)
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        let mut guard = slot.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
            tracing::info!(%peer, "cached connection dead, reconnecting");
        }
        tracing::info!(%peer, "dialing peer");
        let conn = self
            .endpoint
            .connect(peer, TUNNEL_ALPN)
            .await
            .with_context(|| format!("connect to {peer}"))?;
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

pub fn send_packet(conn: &Connection, packet: Bytes) -> anyhow::Result<()> {
    conn.send_datagram(packet)
        .context("send_datagram (packet too big or unsupported)")?;
    Ok(())
}
