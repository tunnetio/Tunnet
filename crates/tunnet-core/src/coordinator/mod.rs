//! Local coordinator: the first process on a machine owns the iroh endpoint;
//! subsequent processes connect as clients and proxy `open_stream` / `list_peers`.
//!
//! - **Unix:** Unix domain socket + `flock`
//! - **Windows:** named pipe + named mutex
//!
//! Wire protocol (newline-delimited JSON), then raw bytes after `Ready`:
//!   client → coord: `{"type":"open_stream","host":"...","port":N}`
//!   coord  → client: `{"type":"ready"}` then bidirectional splice
//!   client → coord: `{"type":"list_peers"}`
//!   coord  → client: `{"type":"peers","peers":[...]}`

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::node::CoreNode;
use crate::stream::dial_stream;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{LockFile, acquire, client_open_stream, connect_client, spawn_coord_server};
#[cfg(windows)]
pub use windows::{LockFile, acquire, client_open_stream, connect_client, spawn_coord_server};

/// Path / pipe name clients use to reach the coordinator.
pub type EndpointPath = PathBuf;

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

/// Result of [`acquire`]: this process is either the coordinator or a client.
pub enum Role {
    Coordinator {
        #[cfg(unix)]
        listener: tokio::net::UnixListener,
        #[cfg(windows)]
        pipe_name: String,
        _lock: LockFile,
        sock_path: EndpointPath,
    },
    Client {
        sock_path: EndpointPath,
    },
}

pub(crate) fn resolve_peer(node: &CoreNode, host: &str) -> Option<Arc<crate::routing::PeerInfo>> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

/// Shared client request handler (Unix UDS or Windows named pipe).
pub(crate) async fn handle_client_rw<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    node: Arc<CoreNode>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let req: ClientReq = serde_json::from_str(line.trim())?;

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
            let mut stream = match dial_stream(
                &node,
                peer.endpoint,
                peer.network_id,
                port,
                host.clone(),
            )
            .await
            {
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
            let mut local = tokio::io::join(local_read, writer);
            tokio::io::copy_bidirectional(&mut stream, &mut local).await?;
            Ok(())
        }
    }
}

/// Default coordinator endpoint path / pipe name for `network_id`.
pub fn default_endpoint_path(network_id: Uuid) -> EndpointPath {
    #[cfg(unix)]
    {
        unix::default_socket_path(network_id)
    }
    #[cfg(windows)]
    {
        windows::default_pipe_path(network_id)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = network_id;
        PathBuf::from("tunnet-unsupported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acquire_first_process_is_coordinator() {
        let id = Uuid::new_v4();
        let role = acquire(id).await.expect("acquire");
        match role {
            Role::Coordinator { sock_path, .. } => {
                assert!(!sock_path.as_os_str().is_empty());
            }
            Role::Client { .. } => panic!("expected coordinator on first acquire"),
        }
    }
}
