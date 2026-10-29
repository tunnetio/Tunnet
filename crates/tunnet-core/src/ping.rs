//! Mesh ping - QUIC RTT over the existing stream ALPN.
//!
//! Not ICMP. Dials `TUNNEL_STREAM_ALPN` with host `__tunnet_ping__`, writes
//! `PING <seq>\n`, waits for `PONG <seq>\n`. Measures true mesh latency.

use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use iroh::EndpointId;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::iroh_pool::ConnPool;
use crate::stream::{StreamHeader, TUNNEL_STREAM_ALPN};

/// Magic host that stream acceptors treat as a ping, not a TCP proxy target.
pub const PING_HOST: &str = "__tunnet_ping__";

pub struct PingResult {
    pub latency_ms: f64,
    /// `"direct"` | `"relayed"` | `"unknown"` when path telemetry is unavailable.
    pub path: String,
}

pub async fn ping_peer(
    pool: &ConnPool,
    peer: EndpointId,
    network: uuid::Uuid,
    seq: u32,
) -> anyhow::Result<PingResult> {
    let conn = pool
        .get_alpn(peer, TUNNEL_STREAM_ALPN)
        .await
        .context("dial ping")?;
    let (mut send, recv) = conn.open_bi().await.context("open_bi ping")?;

    let header = StreamHeader {
        network,
        dst_port: 0,
        host: PING_HOST.into(),
    };
    header.write_to(&mut send).await?;

    let start = Instant::now();
    let msg = format!("PING {seq}\n");
    send.write_all(msg.as_bytes()).await?;
    send.finish()?;

    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .context("ping timeout")??;

    let expected = format!("PONG {seq}");
    if line.trim() != expected {
        bail!("unexpected ping reply: {}", line.trim());
    }

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok(PingResult {
        latency_ms,
        path: "unknown".into(),
    })
}

/// Reply to an inbound ping stream. Returns true if this was a ping.
pub async fn handle_inbound_ping(
    header: &StreamHeader,
    mut send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
) -> bool {
    if header.host != PING_HOST {
        return false;
    }
    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return true;
    }
    let trimmed = line.trim();
    if let Some(seq) = trimmed.strip_prefix("PING ") {
        let reply = format!("PONG {seq}\n");
        let _ = send.write_all(reply.as_bytes()).await;
        let _ = send.finish();
    }
    true
}
