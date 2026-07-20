//! HTTP/1.1 tee: parse + capture while forwarding bytes between relay and local TCP.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::store::{BODY_CAP, CapturedExchange, ExchangeStore};

/// Bidirectional inspect: relay ↔ local TCP, capturing HTTP/1.1 exchanges.
pub async fn inspect_bidirectional<R, W, TR, TW>(
    mut relay_recv: R,
    mut relay_send: W,
    mut tcp_read: TR,
    mut tcp_write: TW,
    mut prefix: Option<Vec<u8>>,
    store: ExchangeStore,
    tunnel_id: String,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    TR: AsyncRead + Unpin,
    TW: AsyncWrite + Unpin,
{
    let mut relay_buf = prefix.take().unwrap_or_default();
    let mut tcp_buf = Vec::new();

    loop {
        let started = Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();

        let req =
            match read_http_message(&mut relay_recv, &mut relay_buf, MessageKind::Request, None)
                .await
            {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) if is_eof(&e) => break,
                Err(e) => return Err(e),
            };

        // Forward full request (headers + body) to local upstream.
        tcp_write.write_all(&req.raw).await?;
        tcp_write.flush().await.ok();

        let is_upgrade = header_has(&req.headers, "upgrade");

        let resp = match read_http_message(
            &mut tcp_read,
            &mut tcp_buf,
            MessageKind::Response,
            Some(req.method.as_str()),
        )
        .await
        {
            Ok(Some(m)) => m,
            Ok(None) => {
                // Upstream closed without a response.
                store.push(CapturedExchange {
                    id: ExchangeStore::new_id(),
                    tunnel_id: tunnel_id.clone(),
                    started_at,
                    method: req.method.clone(),
                    path: req.path.clone(),
                    request_headers: req.headers.clone(),
                    request_body: req.body.clone(),
                    request_body_truncated: req.body_truncated,
                    status: 0,
                    response_headers: vec![],
                    response_body: vec![],
                    response_body_truncated: false,
                    latency_ms: started.elapsed().as_millis() as u64,
                    replayed_from: None,
                });
                break;
            }
            Err(e) if is_eof(&e) => break,
            Err(e) => return Err(e),
        };

        relay_send.write_all(&resp.raw).await?;
        relay_send.flush().await.ok();

        let status = resp.status.unwrap_or(0);
        store.push(CapturedExchange {
            id: ExchangeStore::new_id(),
            tunnel_id: tunnel_id.clone(),
            started_at,
            method: req.method.clone(),
            path: req.path.clone(),
            request_headers: req.headers,
            request_body: req.body,
            request_body_truncated: req.body_truncated,
            status,
            response_headers: resp.headers,
            response_body: resp.body,
            response_body_truncated: resp.body_truncated,
            latency_ms: started.elapsed().as_millis() as u64,
            replayed_from: None,
        });

        // After Upgrade / 101, splice remaining opaque bytes.
        if is_upgrade || status == 101 {
            splice_rest(
                &mut relay_recv,
                &mut relay_send,
                &mut tcp_read,
                &mut tcp_write,
                &mut relay_buf,
                &mut tcp_buf,
            )
            .await?;
            break;
        }

        if !req.keep_alive || !resp.keep_alive {
            break;
        }
    }

    Ok(())
}

/// Replay a captured request against `target`, store the new exchange, return its id.
pub async fn replay_exchange(
    exchange: &CapturedExchange,
    target: SocketAddr,
    store: &ExchangeStore,
) -> anyhow::Result<String> {
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| format!("connect {target}"))?;
    let _ = tcp.set_nodelay(true);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let raw_req = rebuild_request(exchange);
    let started = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    tcp_write.write_all(&raw_req).await?;
    tcp_write.flush().await.ok();

    let mut buf = Vec::new();
    let resp = read_http_message(
        &mut tcp_read,
        &mut buf,
        MessageKind::Response,
        Some(&exchange.method),
    )
    .await?
    .context("upstream closed without response")?;

    let id = ExchangeStore::new_id();
    store.push(CapturedExchange {
        id: id.clone(),
        tunnel_id: exchange.tunnel_id.clone(),
        started_at,
        method: exchange.method.clone(),
        path: exchange.path.clone(),
        request_headers: exchange.request_headers.clone(),
        request_body: exchange.request_body.clone(),
        request_body_truncated: exchange.request_body_truncated,
        status: resp.status.unwrap_or(0),
        response_headers: resp.headers,
        response_body: resp.body,
        response_body_truncated: resp.body_truncated,
        latency_ms: started.elapsed().as_millis() as u64,
        replayed_from: Some(exchange.id.clone()),
    });
    Ok(id)
}

fn rebuild_request(ex: &CapturedExchange) -> Vec<u8> {
    let path = if ex.path.is_empty() { "/" } else { &ex.path };
    let mut clean = Vec::new();
    clean.extend_from_slice(format!("{} {} HTTP/1.1\r\n", ex.method, path).as_bytes());
    let mut has_host = false;
    for (k, v) in &ex.request_headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-length" || lower == "transfer-encoding" || lower == "connection" {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        clean.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        clean.extend_from_slice(b"Host: localhost\r\n");
    }
    clean.extend_from_slice(b"Connection: close\r\n");
    clean
        .extend_from_slice(format!("Content-Length: {}\r\n\r\n", ex.request_body.len()).as_bytes());
    clean.extend_from_slice(&ex.request_body);
    clean
}

#[derive(Clone, Copy)]
enum MessageKind {
    Request,
    Response,
}

struct HttpMessage {
    raw: Vec<u8>,
    method: String,
    path: String,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    body_truncated: bool,
    keep_alive: bool,
}

async fn read_http_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    leftover: &mut Vec<u8>,
    kind: MessageKind,
    request_method: Option<&str>,
) -> anyhow::Result<Option<HttpMessage>> {
    // Accumulate until headers complete.
    loop {
        if let Some(idx) = find_header_end(leftover) {
            return finish_message(reader, leftover, idx, kind, request_method).await;
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            if leftover.is_empty() {
                return Ok(None);
            }
            bail!("unexpected EOF while reading HTTP headers");
        }
        leftover.extend_from_slice(&tmp[..n]);
        if leftover.len() > 256 * 1024 {
            bail!("HTTP headers too large");
        }
    }
}

async fn finish_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    leftover: &mut Vec<u8>,
    header_end: usize,
    kind: MessageKind,
    request_method: Option<&str>,
) -> anyhow::Result<Option<HttpMessage>> {
    let header_bytes = leftover[..header_end].to_vec();
    let after_headers = leftover.split_off(header_end);

    let (method, path, status, headers, version_11) = parse_headers(&header_bytes, kind)?;

    let body_method = match kind {
        MessageKind::Request => method.as_str(),
        MessageKind::Response => request_method.unwrap_or(""),
    };
    let body_info = body_plan(body_method, status, &headers, kind);
    let (body, body_truncated, consumed, raw_body_extra) =
        read_body(reader, after_headers, body_info).await?;

    *leftover = raw_body_extra;

    let mut raw = header_bytes;
    raw.extend_from_slice(&consumed);

    let keep_alive = connection_keep_alive(&headers, version_11)
        && !header_has(&headers, "upgrade")
        && status != Some(101);

    Ok(Some(HttpMessage {
        raw,
        method,
        path,
        status,
        headers,
        body,
        body_truncated,
        keep_alive,
    }))
}

struct BodyPlan {
    mode: BodyMode,
}

enum BodyMode {
    ContentLength(usize),
    Chunked,
    None,
    /// Read until EOF (HTTP/1.0 response without Content-Length).
    UntilEof,
}

fn body_plan(
    method: &str,
    status: Option<u16>,
    headers: &[(String, String)],
    kind: MessageKind,
) -> BodyPlan {
    if matches!(kind, MessageKind::Response) {
        if let Some(s) = status
            && (s == 204 || s == 304 || (100..200).contains(&s))
        {
            return BodyPlan {
                mode: BodyMode::None,
            };
        }
        if method == "HEAD" {
            return BodyPlan {
                mode: BodyMode::None,
            };
        }
    }

    if header_value(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return BodyPlan {
            mode: BodyMode::Chunked,
        };
    }
    if let Some(cl) = header_value(headers, "content-length")
        && let Ok(n) = cl.trim().parse::<usize>()
    {
        return BodyPlan {
            mode: BodyMode::ContentLength(n),
        };
    }
    match kind {
        MessageKind::Request => BodyPlan {
            mode: BodyMode::None,
        },
        MessageKind::Response => BodyPlan {
            mode: BodyMode::UntilEof,
        },
    }
}

/// Returns (captured_body, truncated, wire_bytes_to_append_to_raw, leftover_after_message).
async fn read_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut available: Vec<u8>,
    plan: BodyPlan,
) -> anyhow::Result<(Vec<u8>, bool, Vec<u8>, Vec<u8>)> {
    match plan.mode {
        BodyMode::None => Ok((vec![], false, vec![], available)),
        BodyMode::ContentLength(len) => {
            let mut wire = Vec::with_capacity(len.min(BODY_CAP + 64));
            let mut captured = Vec::new();
            let mut truncated = false;
            let mut remaining = len;

            while remaining > 0 {
                if available.is_empty() {
                    let mut tmp = vec![0u8; 32 * 1024];
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        bail!("unexpected EOF in request/response body");
                    }
                    available.extend_from_slice(&tmp[..n]);
                }
                let take = remaining.min(available.len());
                let chunk = available.drain(..take).collect::<Vec<_>>();
                remaining -= take;
                wire.extend_from_slice(&chunk);
                if captured.len() < BODY_CAP {
                    let space = BODY_CAP - captured.len();
                    let add = chunk.len().min(space);
                    captured.extend_from_slice(&chunk[..add]);
                    if add < chunk.len() {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Ok((captured, truncated || len > BODY_CAP, wire, available))
        }
        BodyMode::Chunked => read_chunked(reader, available).await,
        BodyMode::UntilEof => {
            let mut wire = available;
            let mut captured = Vec::new();
            let mut truncated = false;
            // Seed capture from existing.
            if wire.len() > BODY_CAP {
                captured.extend_from_slice(&wire[..BODY_CAP]);
                truncated = true;
            } else {
                captured.extend_from_slice(&wire);
            }
            loop {
                let mut tmp = [0u8; 32 * 1024];
                let n = reader.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                wire.extend_from_slice(&tmp[..n]);
                if captured.len() < BODY_CAP {
                    let space = BODY_CAP - captured.len();
                    let add = n.min(space);
                    captured.extend_from_slice(&tmp[..add]);
                    if add < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Ok((captured, truncated, wire, Vec::new()))
        }
    }
}

async fn read_chunked<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut available: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, bool, Vec<u8>, Vec<u8>)> {
    let mut wire = Vec::new();
    let mut captured = Vec::new();
    let mut truncated = false;

    loop {
        // Need a chunk-size line.
        let line = loop {
            if let Some(pos) = find_line_end(&available) {
                let line = available[..pos].to_vec();
                let consumed = if available.get(pos..pos + 2) == Some(b"\r\n") {
                    pos + 2
                } else {
                    pos + 1
                };
                wire.extend_from_slice(&available[..consumed]);
                available.drain(..consumed);
                break line;
            }
            let mut tmp = [0u8; 8 * 1024];
            let n = reader.read(&mut tmp).await?;
            if n == 0 {
                bail!("unexpected EOF in chunked body");
            }
            available.extend_from_slice(&tmp[..n]);
        };

        let line_str = std::str::from_utf8(&line).context("chunk size utf8")?;
        let size_hex = line_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).context("parse chunk size")?;

        // Read size bytes + trailing CRLF
        let need = size + 2; // \r\n after chunk
        while available.len() < need {
            let mut tmp = [0u8; 32 * 1024];
            let n = reader.read(&mut tmp).await?;
            if n == 0 {
                bail!("unexpected EOF in chunk data");
            }
            available.extend_from_slice(&tmp[..n]);
        }
        let chunk_data = available.drain(..size).collect::<Vec<_>>();
        // consume \r\n
        if available.len() >= 2 && &available[..2] == b"\r\n" {
            wire.extend_from_slice(&chunk_data);
            wire.extend_from_slice(&available[..2]);
            available.drain(..2);
        } else {
            wire.extend_from_slice(&chunk_data);
            // best-effort
            if available.len() >= 2 {
                wire.extend_from_slice(&available[..2]);
                available.drain(..2);
            }
        }

        if size == 0 {
            // Optional trailers until blank line
            loop {
                if let Some(pos) = find_line_end(&available) {
                    let consumed = if available.get(pos..pos + 2) == Some(b"\r\n") {
                        pos + 2
                    } else {
                        pos + 1
                    };
                    let is_empty = pos == 0 || (pos == 1 && available[0] == b'\r');
                    wire.extend_from_slice(&available[..consumed]);
                    available.drain(..consumed);
                    if is_empty {
                        break;
                    }
                } else {
                    let mut tmp = [0u8; 4 * 1024];
                    let n = reader.read(&mut tmp).await?;
                    if n == 0 {
                        break;
                    }
                    available.extend_from_slice(&tmp[..n]);
                }
            }
            break;
        }

        if captured.len() < BODY_CAP {
            let space = BODY_CAP - captured.len();
            let add = chunk_data.len().min(space);
            captured.extend_from_slice(&chunk_data[..add]);
            if add < chunk_data.len() {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok((captured, truncated, wire, available))
}

type ParsedHeaders = (String, String, Option<u16>, Vec<(String, String)>, bool);

fn parse_headers(header_bytes: &[u8], kind: MessageKind) -> anyhow::Result<ParsedHeaders> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    match kind {
        MessageKind::Request => {
            let mut req = httparse::Request::new(&mut headers_buf);
            match req.parse(header_bytes).context("parse request")? {
                httparse::Status::Complete(_) => {}
                httparse::Status::Partial => bail!("incomplete request headers"),
            }
            let method = req.method.unwrap_or("GET").to_string();
            let path = req.path.unwrap_or("/").to_string();
            let version_11 = req.version.unwrap_or(1) == 1;
            let headers = collect_headers(req.headers);
            Ok((method, path, None, headers, version_11))
        }
        MessageKind::Response => {
            let mut res = httparse::Response::new(&mut headers_buf);
            match res.parse(header_bytes).context("parse response")? {
                httparse::Status::Complete(_) => {}
                httparse::Status::Partial => bail!("incomplete response headers"),
            }
            let status = res.code;
            let version_11 = res.version.unwrap_or(1) == 1;
            let headers = collect_headers(res.headers);
            Ok((String::new(), String::new(), status, headers, version_11))
        }
    }
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn find_line_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2)
        .position(|w| w == b"\r\n")
        .or_else(|| buf.iter().position(|&b| b == b'\n'))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_has(headers: &[(String, String)], name: &str) -> bool {
    header_value(headers, name).is_some()
}

fn connection_keep_alive(headers: &[(String, String)], http11: bool) -> bool {
    match header_value(headers, "connection").map(|v| v.to_ascii_lowercase()) {
        Some(v) if v.contains("close") => false,
        Some(v) if v.contains("keep-alive") => true,
        _ => http11,
    }
}

fn is_eof(e: &anyhow::Error) -> bool {
    e.downcast_ref::<io::Error>()
        .map(|e| e.kind() == io::ErrorKind::UnexpectedEof)
        .unwrap_or(false)
}

async fn splice_rest<R, W, TR, TW>(
    relay_recv: &mut R,
    relay_send: &mut W,
    tcp_read: &mut TR,
    tcp_write: &mut TW,
    relay_buf: &mut Vec<u8>,
    tcp_buf: &mut Vec<u8>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    TR: AsyncRead + Unpin,
    TW: AsyncWrite + Unpin,
{
    if !relay_buf.is_empty() {
        tcp_write.write_all(relay_buf).await?;
        relay_buf.clear();
    }
    if !tcp_buf.is_empty() {
        relay_send.write_all(tcp_buf).await?;
        tcp_buf.clear();
    }

    let up = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = relay_recv.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tcp_write.write_all(&buf[..n]).await?;
        }
        tcp_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            relay_send.write_all(&buf[..n]).await?;
        }
        relay_send.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    let (a, b) = tokio::join!(up, down);
    a?;
    b?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn parse_get_request_no_body() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_slice());
        let mut leftover = Vec::new();
        let msg = read_http_message(&mut cursor, &mut leftover, MessageKind::Request, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.method, "GET");
        assert_eq!(msg.path, "/hello");
        assert!(msg.body.is_empty());
        assert!(!msg.body_truncated);
        assert_eq!(&msg.raw[..], &raw[..]);
    }

    #[tokio::test]
    async fn parse_post_content_length() {
        let raw = b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = Cursor::new(raw.as_slice());
        let mut leftover = Vec::new();
        let msg = read_http_message(&mut cursor, &mut leftover, MessageKind::Request, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.method, "POST");
        assert_eq!(msg.body, b"hello");
        assert!(!msg.body_truncated);
    }

    #[tokio::test]
    async fn truncate_large_body() {
        let body = vec![b'a'; BODY_CAP + 100];
        let header = format!(
            "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let header_len = header.len();
        let mut raw = header.into_bytes();
        raw.extend_from_slice(&body);
        let mut cursor = Cursor::new(raw);
        let mut leftover = Vec::new();
        let msg = read_http_message(&mut cursor, &mut leftover, MessageKind::Request, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.body.len(), BODY_CAP);
        assert!(msg.body_truncated);
        assert_eq!(msg.raw.len(), header_len + body.len());
    }

    #[tokio::test]
    async fn parse_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_slice());
        let mut leftover = Vec::new();
        let msg = read_http_message(
            &mut cursor,
            &mut leftover,
            MessageKind::Response,
            Some("GET"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(msg.status, Some(200));
        assert_eq!(msg.body, b"hello");
        assert!(!msg.body_truncated);
    }

    #[tokio::test]
    async fn keep_alive_two_requests() {
        let raw = concat!(
            "GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
            "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let mut cursor = Cursor::new(raw.as_bytes());
        let mut leftover = Vec::new();
        let a = read_http_message(&mut cursor, &mut leftover, MessageKind::Request, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.path, "/a");
        assert!(a.keep_alive);
        let b = read_http_message(&mut cursor, &mut leftover, MessageKind::Request, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b.path, "/b");
        assert!(!b.keep_alive);
    }
}
