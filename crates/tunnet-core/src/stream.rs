use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::{BufMut, BytesMut};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TUNNEL_STREAM_ALPN: &[u8] = b"tunnet/stream/1";

pub const PROTO_VERSION: u8 = 1;
pub const MAX_HOST_LEN: usize = 253;

pub struct StreamHeader {
    pub dst_port: u16,
    pub host: String,
}

impl StreamHeader {
    pub async fn write_to(&self, send: &mut SendStream) -> anyhow::Result<()> {
        if self.host.len() > MAX_HOST_LEN {
            bail!("host too long");
        }
        let mut buf = BytesMut::with_capacity(5 + self.host.len());
        buf.put_u8(PROTO_VERSION);
        buf.put_u16(self.dst_port);
        buf.put_u16(self.host.len() as u16);
        buf.extend_from_slice(self.host.as_bytes());
        send.write_all(&buf).await.context("write header")?;
        Ok(())
    }

    pub async fn read_from(recv: &mut RecvStream) -> anyhow::Result<Self> {
        let mut prefix = [0u8; 5];
        recv.read_exact(&mut prefix)
            .await
            .context("read header prefix")?;
        if prefix[0] != PROTO_VERSION {
            bail!("unsupported stream proto version {}", prefix[0]);
        }
        let dst_port = u16::from_be_bytes([prefix[1], prefix[2]]);
        let host_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
        if host_len > MAX_HOST_LEN {
            bail!("host too long ({host_len})");
        }
        let mut host = vec![0u8; host_len];
        if host_len > 0 {
            recv.read_exact(&mut host).await.context("read host")?;
        }
        Ok(Self {
            dst_port,
            host: String::from_utf8(host).context("host utf8")?,
        })
    }
}

pub async fn dial_stream(
    pool: &crate::iroh_pool::ConnPool,
    peer: EndpointId,
    dst_port: u16,
    host: String,
) -> anyhow::Result<(SendStream, RecvStream)> {
    let conn = pool.get_alpn(peer, TUNNEL_STREAM_ALPN).await?;
    let (mut send, recv) = conn.open_bi().await.context("open_bi")?;
    let header = StreamHeader { dst_port, host };
    header.write_to(&mut send).await?;
    Ok((send, recv))
}

pub type StreamHandler = Arc<
    dyn Fn(AcceptedStream) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>
        + Send
        + Sync
        + 'static,
>;

pub struct AcceptedStream {
    pub peer: EndpointId,
    pub peer_hex: String,
    pub header: StreamHeader,
    pub send: SendStream,
    pub recv: RecvStream,
}

/// Handle an already-accepted connection negotiated with [`TUNNEL_STREAM_ALPN`].
pub async fn serve_stream_connection(conn: Connection, handler: StreamHandler) {
    let peer = conn.remote_id();
    let peer_hex = format!("{peer}");
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(%peer_hex, ?e, "accept_bi closed");
                break;
            }
        };
        let header = match StreamHeader::read_from(&mut recv).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(%peer_hex, ?e, "bad stream header");
                continue;
            }
        };
        let accepted = AcceptedStream {
            peer,
            peer_hex: peer_hex.clone(),
            header,
            send,
            recv,
        };
        let h = handler.clone();
        tokio::spawn(async move { h(accepted).await });
    }
}

/// [`ProtocolHandler`] for [`TUNNEL_STREAM_ALPN`].
#[derive(Clone)]
pub struct StreamProtocolHandler {
    handler: StreamHandler,
}

impl StreamProtocolHandler {
    pub fn new(handler: StreamHandler) -> Self {
        Self { handler }
    }
}

impl fmt::Debug for StreamProtocolHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamProtocolHandler")
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for StreamProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        serve_stream_connection(connection, self.handler.clone()).await;
        Ok(())
    }
}

pub async fn splice_bidirectional<R, W>(
    mut recv: RecvStream,
    mut send: SendStream,
    mut local_read: R,
    mut local_write: W,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let up = async move {
        // local → remote
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        send.finish().ok();
        Ok::<_, anyhow::Error>(())
    };
    let down = async move {
        // remote → local
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match recv.read(&mut buf).await? {
                Some(n) => n,
                None => break,
            };
            local_write.write_all(&buf[..n]).await?;
        }
        local_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let (a, b) = tokio::join!(up, down);
    a?;
    b?;
    Ok(())
}
