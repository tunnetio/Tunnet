use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

const ALPN: &[u8] = b"tunnet/quic-bench";

#[derive(Debug, Serialize, Deserialize)]
struct Workload {
    reverse: bool,
    mbps: u32,
    seconds: u32,
    size: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Sent {
    datagrams: u64,
    bytes: u64,
    elapsed_seconds: f64,
    drain_seconds: f64,
    queued_bytes_after_drain: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Received {
    datagrams: u64,
    bytes: u64,
    reordered: u64,
    arrival_span_seconds: f64,
    sent: Sent,
}

impl Received {
    fn print(&self, direction: &str) {
        let loss = self.sent.datagrams.saturating_sub(self.datagrams);
        println!(
            "{}",
            serde_json::json!({
                "direction": direction,
                "quic_accepted_datagrams": self.sent.datagrams,
                "received_datagrams": self.datagrams,
                "quic_accepted_bytes": self.sent.bytes,
                "received_bytes": self.bytes,
                "unreceived_accepted_datagrams": loss,
                "unreceived_percent": loss as f64 * 100.0 / self.sent.datagrams.max(1) as f64,
                "queue_drained": self.sent.queued_bytes_after_drain == 0,
                "queued_bytes_after_drain": self.sent.queued_bytes_after_drain,
                "drain_seconds": self.sent.drain_seconds,
                "arrival_span_seconds": self.arrival_span_seconds,
                "reordered": self.reordered,
                "elapsed_seconds": self.sent.elapsed_seconds,
                "received_mbps": self.bytes as f64 * 8.0 / self.arrival_span_seconds.max(0.001) / 1_000_000.0,
            })
        );
    }
}

async fn write_message<T: Serialize>(stream: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_message<T: serde::de::DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= 65536, "control message too large");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn connection_state(conn: &Connection, stage: &str) {
    let paths = conn.paths();
    let selected = paths.iter().find(|path| path.is_selected());
    let path_stats = selected.as_ref().map(|path| path.stats());
    println!(
        "{}",
        serde_json::json!({
            "stage": stage,
            "selected_remote_addr": selected.as_ref().map(|path| format!("{:?}", path.remote_addr())),
            "selected_is_relay": selected.as_ref().map(|path| path.is_relay()),
            "selected_rtt_us": path_stats.as_ref().map(|stats| stats.rtt.as_micros()),
            "selected_cwnd_bytes": path_stats.as_ref().map(|stats| stats.cwnd),
            "selected_udp_mtu": path_stats.as_ref().map(|stats| stats.current_mtu),
            "max_datagram_size": conn.max_datagram_size(),
            "send_buffer_available_bytes": conn.datagram_send_buffer_space(),
            "stats": format!("{:?}", conn.stats()),
        })
    );
}

async fn send(conn: &Connection, workload: &Workload) -> Result<Sent> {
    ensure!(
        conn.max_datagram_size()
            .is_some_and(|max| workload.size <= max),
        "requested datagram size exceeds current path maximum"
    );
    let start = Instant::now();
    let finish = start + Duration::from_secs(u64::from(workload.seconds));
    let bytes_per_second = u64::from(workload.mbps) * 125_000;
    let mut sent = Sent::default();
    let mut payload = vec![0x42; workload.size];
    let capacity = conn.datagram_send_buffer_space();
    let mut lowest_space = capacity;
    while Instant::now() < finish {
        let elapsed = start.elapsed().as_secs_f64();
        let allowed = (elapsed * bytes_per_second as f64) as u64
            + (bytes_per_second / 1000).max(workload.size as u64);
        for _ in 0..32 {
            if sent.bytes >= allowed || Instant::now() >= finish {
                break;
            }
            payload[..8].copy_from_slice(&sent.datagrams.to_be_bytes());
            lowest_space = lowest_space.min(conn.datagram_send_buffer_space());
            tokio::time::timeout(
                Duration::from_secs(5),
                conn.send_datagram_wait(Bytes::copy_from_slice(&payload)),
            )
            .await??;
            sent.datagrams += 1;
            sent.bytes += workload.size as u64;
        }
        if sent.bytes >= allowed {
            tokio::time::sleep_until(
                (start + Duration::from_secs_f64(sent.bytes as f64 / bytes_per_second as f64))
                    .min(finish),
            )
            .await;
        } else {
            tokio::task::yield_now().await;
        }
    }
    sent.elapsed_seconds = start.elapsed().as_secs_f64();
    let drain_start = Instant::now();
    while conn.datagram_send_buffer_space() < capacity
        && drain_start.elapsed() < Duration::from_secs(15)
    {
        ensure!(
            conn.close_reason().is_none(),
            "connection closed during queue drain"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sent.drain_seconds = drain_start.elapsed().as_secs_f64();
    sent.queued_bytes_after_drain = capacity.saturating_sub(conn.datagram_send_buffer_space());
    println!("lowest_send_buffer_available_bytes={lowest_space}");
    Ok(sent)
}

async fn receive(conn: &Connection, control: &mut RecvStream, seconds: u32) -> Result<Received> {
    let mut result = Received::default();
    let completion = read_message::<Sent>(control);
    tokio::pin!(completion);
    let mut done = false;
    let mut deadline = Instant::now() + Duration::from_secs(u64::from(seconds) + 45);
    let mut maximum_sequence = None;
    let mut first_arrival = None;
    loop {
        tokio::select! {
            biased;
            sent = &mut completion, if !done => {
                result.sent = sent?;
                done = true;
                deadline = Instant::now() + Duration::from_millis(750);
            }
            _ = tokio::time::sleep_until(deadline) => break,
            datagram = conn.read_datagram() => {
                let datagram = datagram?;
                ensure!(datagram.len() >= 8, "short benchmark datagram");
                let sequence = u64::from_be_bytes(datagram[..8].try_into()?);
                if maximum_sequence.is_some_and(|maximum| sequence < maximum) { result.reordered += 1; }
                maximum_sequence = Some(maximum_sequence.map_or(sequence, |maximum: u64| maximum.max(sequence)));
                let first = first_arrival.get_or_insert_with(Instant::now);
                result.arrival_span_seconds = first.elapsed().as_secs_f64();
                result.datagrams += 1;
                result.bytes += datagram.len() as u64;
            }
        }
    }
    ensure!(done, "sender completion timed out");
    Ok(result)
}

async fn serve(conn: Connection) -> Result<()> {
    connection_state(&conn, "server_connected");
    let (mut tx, mut rx) = conn.accept_bi().await?;
    let workload: Workload = read_message(&mut rx).await?;
    validate(&workload)?;
    write_message(&mut tx, &true).await?;
    if workload.reverse {
        let sent = send(&conn, &workload).await?;
        write_message(&mut tx, &sent).await?;
        let received: Received = read_message(&mut rx).await?;
        received.print("server_to_client");
    } else {
        let received = receive(&conn, &mut rx, workload.seconds).await?;
        received.print("client_to_server");
        write_message(&mut tx, &received).await?;
    }
    connection_state(&conn, "server_finished");
    tx.finish()?;
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    Ok(())
}

fn validate(workload: &Workload) -> Result<()> {
    ensure!(
        (1..=10000).contains(&workload.mbps),
        "mbps outside 1..=10000"
    );
    ensure!(
        (1..=300).contains(&workload.seconds),
        "seconds outside 1..=300"
    );
    ensure!(
        (8..=65500).contains(&workload.size),
        "size outside 8..=65500"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let option = |key: &str| {
        args.windows(2)
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1].as_str())
    };
    let mode = args.get(1).context("server --port PORT | client --peer ID --addr IP:PORT [--bind IP --interface INDEX] [--reverse] [--mbps 100] [--seconds 10] [--size 1100]")?;
    let port: u16 = option("--port").unwrap_or("0").parse()?;
    let bind_ip: IpAddr = option("--bind").unwrap_or("127.0.0.1").parse()?;
    let interface = option("--interface")
        .map(|value| -> Result<_> {
            let index = NonZeroU32::new(value.parse()?).context("zero interface index")?;
            Ok(iroh::endpoint::InterfaceBinding::new(index)?)
        })
        .transpose()?;
    ensure!(
        bind_ip.is_loopback() || interface.is_some(),
        "non-loopback benchmark requires --interface"
    );
    ensure!(
        !bind_ip.is_unspecified(),
        "benchmark requires a concrete --bind address"
    );
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr_with_opts(
            SocketAddr::new(bind_ip, port),
            iroh::endpoint::BindOpts::default().set_socket_config(iroh::endpoint::SocketConfig {
                interface,
                initialize: None,
            }),
        )?
        .bind()
        .await?;
    println!(
        "endpoint_id={} endpoint_addr={:?}",
        endpoint.id(),
        endpoint.addr()
    );
    match mode.as_str() {
        "server" => {
            ensure!(port != 0, "server requires explicit --port");
            while let Some(incoming) = endpoint.accept().await {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(error) = serve(conn).await {
                            eprintln!("benchmark_failed={error:#}");
                        }
                    }
                    Err(error) => eprintln!("connection_failed={error}"),
                }
            }
        }
        "client" => {
            let peer: EndpointId = option("--peer").context("missing --peer")?.parse()?;
            let addr: SocketAddr = option("--addr").context("missing --addr")?.parse()?;
            let workload = Workload {
                reverse: args.iter().any(|arg| arg == "--reverse"),
                mbps: option("--mbps").unwrap_or("100").parse()?,
                seconds: option("--seconds").unwrap_or("10").parse()?,
                size: option("--size").unwrap_or("1100").parse()?,
            };
            validate(&workload)?;
            let conn = endpoint
                .connect(EndpointAddr::new(peer).with_ip_addr(addr), ALPN)
                .await?;
            connection_state(&conn, "client_connected");
            let (mut tx, mut rx) = conn.open_bi().await?;
            write_message(&mut tx, &workload).await?;
            ensure!(
                read_message::<bool>(&mut rx).await?,
                "server refused workload"
            );
            if workload.reverse {
                let received = receive(&conn, &mut rx, workload.seconds).await?;
                received.print("server_to_client");
                write_message(&mut tx, &received).await?;
            } else {
                let sent = send(&conn, &workload).await?;
                write_message(&mut tx, &sent).await?;
                let received: Received = read_message(&mut rx).await?;
                received.print("client_to_server");
            }
            tx.finish()?;
            connection_state(&conn, "client_finished");
            tokio::time::sleep(Duration::from_millis(100)).await;
            conn.close(0u32.into(), b"done");
        }
        _ => anyhow::bail!("unknown mode {mode}"),
    }
    endpoint.close().await;
    Ok(())
}
