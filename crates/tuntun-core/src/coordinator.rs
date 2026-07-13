//! Local coordinator: the first process on a machine opens a UDS server;
//! subsequent processes connect as clients. Ownership races are resolved
//! via a lock file. All processes share the single iroh endpoint owned by
//! the coordinator.
//!
//! Wire protocol on the UDS (newline-delimited JSON):
//!   client → coord: {"type":"open_stream","host":"<peer-host-or-ip>","port":<u16>}
//!   coord  → client: {"type":"ready"}    then raw bytes stream over the socket
//!                    (bidirectional splice: UDS ↔ QUIC stream)
//!   coord  → client: {"type":"error","message":"..."}
//!
//!   client → coord: {"type":"list_peers"}
//!   coord  → client: {"type":"peers","peers":[{...}]}
//!
//! Note: on Windows there are no UDS in the same way. This module is
//! `cfg(unix)`; the Windows implementation should use a named pipe. That's
//! out of scope for this initial cut.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use crate::node::CoreNode;
use crate::stream::{dial_stream, splice_bidirectional};

pub fn default_socket_path(network_id: Uuid) -> PathBuf {
    let base = std::env::var("TUNTUN_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(base).join(format!("tuntun-{network_id}.sock"))
}

pub fn default_lock_path(network_id: Uuid) -> PathBuf {
    let base = std::env::var("TUNTUN_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(base).join(format!("tuntun-{network_id}.lock"))
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientReq {
    OpenStream { host: String, port: u16 },
    ListPeers,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordResp {
    Ready,
    Peers { peers: Vec<PeerLite> },
    Error { message: String },
}

#[derive(Serialize, Deserialize)]
pub struct PeerLite {
    pub ip: String,
    pub hostname: String,
    pub endpoint_id: String,
    pub tags: Vec<String>,
}

pub enum Role {
    Coordinator {
        listener: UnixListener,
        _lock: LockFile,
        sock_path: PathBuf,
    },
    Client {
        conn: UnixStream,
        sock_path: PathBuf,
    },
}

pub async fn acquire(network_id: Uuid) -> anyhow::Result<Role> {
    let sock = default_socket_path(network_id);
    let lock = default_lock_path(network_id);

    for _ in 0..5 {
        if sock.exists() {
            match UnixStream::connect(&sock).await {
                Ok(conn) => {
                    return Ok(Role::Client {
                        conn,
                        sock_path: sock,
                    });
                }
                Err(e) => {
                    tracing::debug!(?e, "sock exists but connect failed; will try coord");
                    let _ = std::fs::remove_file(&sock);
                }
            }
        }
        match LockFile::acquire(&lock) {
            Ok(l) => {
                let _ = std::fs::remove_file(&sock);
                let listener = UnixListener::bind(&sock)
                    .with_context(|| format!("bind {}", sock.display()))?;
                tracing::info!(path = %sock.display(), "became coordinator");
                return Ok(Role::Coordinator {
                    listener,
                    _lock: l,
                    sock_path: sock,
                });
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
    }
    bail!("could not acquire coordinator or client role after retries")
}

pub struct LockFile {
    _fd: i32,
    path: PathBuf,
}

impl LockFile {
    pub fn acquire(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(path)?;
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!("flock: another coordinator holds {}", path.display());
        }
        std::mem::forget(file);
        Ok(Self {
            _fd: fd,
            path: path.to_path_buf(),
        })
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn spawn_coord_server(listener: UnixListener, node: Arc<CoreNode>) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(sock, node).await {
                            tracing::warn!(?e, "coord client handling failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(?e, "coord accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    });
}

async fn handle_client(sock: UnixStream, node: Arc<CoreNode>) -> anyhow::Result<()> {
    let (read, write) = sock.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let req: ClientReq = serde_json::from_str(line.trim())?;
    let mut writer = write;

    match req {
        ClientReq::ListPeers => {
            let peers = node
                .routes
                .peers()
                .into_iter()
                .map(|p| PeerLite {
                    ip: p.ip.to_string(),
                    hostname: p.hostname.clone(),
                    endpoint_id: p.endpoint_hex.clone(),
                    tags: p.tags.clone(),
                })
                .collect();
            let resp = CoordResp::Peers { peers };
            let mut txt = serde_json::to_vec(&resp)?;
            txt.push(b'\n');
            writer.write_all(&txt).await?;
            Ok(())
        }
        ClientReq::OpenStream { host, port } => {
            let peer = resolve_peer(&node, &host)
                .ok_or_else(|| anyhow::anyhow!("no peer matches host {host}"))?;
            let (send, recv) =
                match dial_stream(&node.pool, peer.endpoint, port, host.clone()).await {
                    Ok(x) => x,
                    Err(e) => {
                        let resp = CoordResp::Error {
                            message: e.to_string(),
                        };
                        let mut txt = serde_json::to_vec(&resp)?;
                        txt.push(b'\n');
                        let _ = writer.write_all(&txt).await;
                        return Err(e);
                    }
                };
            let resp = CoordResp::Ready;
            let mut txt = serde_json::to_vec(&resp)?;
            txt.push(b'\n');
            writer.write_all(&txt).await?;

            let local_read = reader.into_inner();
            let local_write = writer;
            splice_bidirectional(recv, send, local_read, local_write).await
        }
    }
}

fn resolve_peer(node: &CoreNode, host: &str) -> Option<Arc<crate::routing::PeerInfo>> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

pub async fn client_open_stream(sock: &Path, host: &str, port: u16) -> anyhow::Result<UnixStream> {
    let mut conn = UnixStream::connect(sock).await?;
    let req = ClientReq::OpenStream {
        host: host.into(),
        port,
    };
    let mut buf = serde_json::to_vec(&req)?;
    buf.push(b'\n');
    conn.write_all(&buf).await?;

    let mut br = BufReader::new(conn);
    let mut line = String::new();
    br.read_line(&mut line).await?;
    let resp: CoordResp = serde_json::from_str(line.trim())?;
    match resp {
        CoordResp::Ready => Ok(br.into_inner()),
        CoordResp::Error { message } => bail!("coord error: {message}"),
        CoordResp::Peers { .. } => bail!("unexpected peers response"),
    }
}
