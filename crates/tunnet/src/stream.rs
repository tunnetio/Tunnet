//! Bidirectional mesh byte streams.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tunnet_core::stream::AuthorizedStream;

/// A bidirectional byte stream to a mesh peer.
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] so it composes with the tokio ecosystem
/// (`copy_bidirectional`, `BufReader`, etc.).
pub struct TunnetStream {
    inner: StreamInner,
}

enum StreamInner {
    Mesh(AuthorizedStream),
    #[cfg(unix)]
    Local {
        sock: tokio::net::UnixStream,
        leftover: Vec<u8>,
    },
    #[cfg(windows)]
    Local {
        sock: tokio::net::windows::named_pipe::NamedPipeClient,
        leftover: Vec<u8>,
    },
}

impl TunnetStream {
    pub(crate) fn from_authorized(stream: AuthorizedStream) -> Self {
        Self {
            inner: StreamInner::Mesh(stream),
        }
    }

    #[cfg(unix)]
    pub(crate) fn from_local(sock: tokio::net::UnixStream, leftover: Vec<u8>) -> Self {
        Self {
            inner: StreamInner::Local { sock, leftover },
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_local(
        sock: tokio::net::windows::named_pipe::NamedPipeClient,
        leftover: Vec<u8>,
    ) -> Self {
        Self {
            inner: StreamInner::Local { sock, leftover },
        }
    }
}

impl AsyncRead for TunnetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Mesh(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(any(unix, windows))]
            StreamInner::Local { sock, leftover } => {
                if !leftover.is_empty() {
                    let n = buf.remaining().min(leftover.len());
                    buf.put_slice(&leftover[..n]);
                    leftover.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                Pin::new(sock).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for TunnetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            StreamInner::Mesh(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(any(unix, windows))]
            StreamInner::Local { sock, .. } => Pin::new(sock).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Mesh(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(any(unix, windows))]
            StreamInner::Local { sock, .. } => Pin::new(sock).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Mesh(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(any(unix, windows))]
            StreamInner::Local { sock, .. } => Pin::new(sock).poll_shutdown(cx),
        }
    }
}
