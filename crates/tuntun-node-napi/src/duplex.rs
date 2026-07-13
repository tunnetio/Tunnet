use anyhow::Result;
use iroh::endpoint::{RecvStream, SendStream};
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub enum Duplex {
    Iroh {
        send: SendStream,
        recv: RecvStream,
    },
    #[cfg(unix)]
    Uds {
        sock: tokio::net::UnixStream,
        leftover: Vec<u8>,
    },
}

impl Duplex {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Duplex::Iroh { recv, .. } => Ok(recv.read(buf).await?.unwrap_or(0)),
            #[cfg(unix)]
            Duplex::Uds { sock, leftover } => {
                if !leftover.is_empty() {
                    let n = buf.len().min(leftover.len());
                    buf[..n].copy_from_slice(&leftover[..n]);
                    leftover.drain(..n);
                    return Ok(n);
                }
                Ok(sock.read(buf).await?)
            }
        }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Duplex::Iroh { send, .. } => Ok(send.write_all(data).await?),
            #[cfg(unix)]
            Duplex::Uds { sock, .. } => Ok(sock.write_all(data).await?),
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Duplex::Iroh { send, .. } => {
                send.finish().ok();
                Ok(())
            }
            #[cfg(unix)]
            Duplex::Uds { sock, .. } => Ok(sock.shutdown().await?),
        }
    }
}
