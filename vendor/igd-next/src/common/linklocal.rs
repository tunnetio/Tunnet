//! Helpers for reaching a gateway at an IPv6 link-local address.
//!
//! A link-local (`FE80::/10`) gateway can only be reached on a specific interface, identified by
//! the address's zone (scope) id. The HTTP clients used elsewhere resolve the URL host themselves
//! and cannot carry that zone id, so for a link-local gateway we connect to the scoped socket
//! address directly and speak a minimal HTTP/1.1 ourselves.

use std::net::{Ipv6Addr, SocketAddr};

/// Whether `addr` is an IPv6 link-local address (`FE80::/10`) carrying a non-zero zone (scope) id.
pub fn is_scoped_link_local(addr: &SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(a) if is_link_local(a.ip()) && a.scope_id() != 0)
}

/// If `addr` is an IPv6 link-local address without a zone id, inherit it from `from` (the address an
/// SSDP response was received from) so the gateway can later be reached on that interface. Any other
/// address is returned unchanged.
pub fn apply_response_scope(addr: SocketAddr, from: SocketAddr) -> SocketAddr {
    if let (SocketAddr::V6(mut a), SocketAddr::V6(f)) = (addr, from) {
        if is_link_local(a.ip()) && a.scope_id() == 0 && f.scope_id() != 0 {
            a.set_scope_id(f.scope_id());
            return SocketAddr::V6(a);
        }
    }
    addr
}

/// The URL / `Host`-header form of `addr` with any IPv6 zone id omitted (`[fe80::1]:1900`).
pub fn host_without_zone(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => a.to_string(),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

pub fn is_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Send an HTTP request to a scoped gateway and return its response body.
/// The timeout covers the full request and response.
#[cfg(feature = "io_sync")]
pub fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
    timeout: std::time::Duration,
    max_body: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Write};
    use std::net::TcpStream;
    use std::time::Instant;

    if !path.starts_with('/')
        || path.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        || extra_headers.iter().any(|(name, value)| {
            name.bytes()
                .chain(value.bytes())
                .any(|byte| byte == b'\r' || byte == b'\n')
        })
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid HTTP request target or header",
        ));
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid HTTP timeout"))?;

    let host = host_without_zone(&addr);
    let mut stream = TcpStream::connect_timeout(&addr, remaining(deadline)?)?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    let mut written = 0;
    while written < request.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = stream.write(&request.as_bytes()[written..])?;
        if count == 0 {
            return Err(Error::new(ErrorKind::WriteZero, "could not send HTTP request"));
        }
        written += count;
    }

    let mut raw = Vec::new();
    let header_end = loop {
        if let Some(end) = find_subsequence(&raw, b"\r\n\r\n") {
            if end > 16 * 1024 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "HTTP response headers are too large",
                ));
            }
            break end;
        }
        if raw.len() > 16 * 1024 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "HTTP response headers are too large",
            ));
        }
        if read_more(&mut stream, &mut raw, deadline)? == 0 {
            return Err(Error::new(ErrorKind::InvalidData, "malformed HTTP response"));
        }
    };
    let headers = &raw[..header_end];
    let framing = response_framing(headers)?;
    let body_start = header_end + 4;

    match framing {
        ResponseFraming::Length(length) => {
            if length > max_body {
                return Err(body_too_large());
            }
            while raw.len() - body_start < length {
                if read_more(&mut stream, &mut raw, deadline)? == 0 {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP response body"));
                }
            }
            Ok(raw[body_start..body_start + length].to_vec())
        }
        ResponseFraming::Chunked => {
            let mut scanner = ChunkScanner::default();
            loop {
                if let Some(end) = scanner.advance(&raw[body_start..])? {
                    if end > max_body {
                        return Err(body_too_large());
                    }
                    return dechunk(&raw[body_start..body_start + end]);
                }
                if raw.len() - body_start > max_body {
                    return Err(body_too_large());
                }
                if read_more(&mut stream, &mut raw, deadline)? == 0 {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "incomplete chunked response"));
                }
            }
        }
        ResponseFraming::Close => {
            while raw.len() - body_start <= max_body {
                if read_more(&mut stream, &mut raw, deadline)? == 0 {
                    return Ok(raw[body_start..].to_vec());
                }
            }
            Err(body_too_large())
        }
    }
}

#[cfg(feature = "io_sync")]
fn remaining(deadline: std::time::Instant) -> std::io::Result<std::time::Duration> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "HTTP request timed out",
        ))
    } else {
        Ok(left)
    }
}

#[cfg(feature = "io_sync")]
fn read_more(
    stream: &mut std::net::TcpStream,
    raw: &mut Vec<u8>,
    deadline: std::time::Instant,
) -> std::io::Result<usize> {
    use std::io::Read;
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut buffer = [0u8; 8192];
    let count = stream.read(&mut buffer)?;
    raw.extend_from_slice(&buffer[..count]);
    Ok(count)
}

#[cfg(feature = "io_sync")]
fn body_too_large() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "gateway response body exceeded the maximum allowed size",
    )
}

#[cfg(feature = "io_sync")]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(feature = "io_sync")]
enum ResponseFraming {
    Length(usize),
    Chunked,
    Close,
}

#[cfg(feature = "io_sync")]
fn response_framing(headers: &[u8]) -> std::io::Result<ResponseFraming> {
    use std::io::{Error, ErrorKind};

    let mut length = None;
    let mut chunked = false;
    for line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(split) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..split];
        let value = std::str::from_utf8(&line[split + 1..])
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid HTTP response header"))?
            .trim();
        if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(Error::new(ErrorKind::InvalidData, "duplicate content length"));
            }
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid content length"))?,
            );
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") || chunked {
                return Err(Error::new(ErrorKind::InvalidData, "unsupported transfer encoding"));
            }
            chunked = true;
        }
    }
    match (chunked, length) {
        (true, Some(_)) => Err(Error::new(ErrorKind::InvalidData, "ambiguous HTTP response framing")),
        (true, None) => Ok(ResponseFraming::Chunked),
        (false, Some(length)) => Ok(ResponseFraming::Length(length)),
        (false, None) => Ok(ResponseFraming::Close),
    }
}

#[cfg(feature = "io_sync")]
#[derive(Default)]
struct ChunkScanner {
    offset: usize,
    state: ChunkState,
}

#[cfg(feature = "io_sync")]
#[derive(Default)]
enum ChunkState {
    #[default]
    Size,
    Data(usize),
    DataEnd,
    Trailer,
}

#[cfg(feature = "io_sync")]
impl ChunkScanner {
    fn advance(&mut self, body: &[u8]) -> std::io::Result<Option<usize>> {
        use std::io::{Error, ErrorKind};

        let invalid = || Error::new(ErrorKind::InvalidData, "malformed chunked response");
        loop {
            match self.state {
                ChunkState::Size => {
                    let Some(line_end) = find_subsequence(&body[self.offset..], b"\r\n") else {
                        return Ok(None);
                    };
                    let line =
                        std::str::from_utf8(&body[self.offset..self.offset + line_end]).map_err(|_| invalid())?;
                    let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                        .map_err(|_| invalid())?;
                    self.offset += line_end + 2;
                    self.state = if size == 0 {
                        ChunkState::Trailer
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(left) => {
                    let count = left.min(body.len() - self.offset);
                    self.offset += count;
                    self.state = if count == left {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left - count)
                    };
                    if count < left {
                        return Ok(None);
                    }
                }
                ChunkState::DataEnd => {
                    if body.len() - self.offset < 2 {
                        return Ok(None);
                    }
                    if &body[self.offset..self.offset + 2] != b"\r\n" {
                        return Err(invalid());
                    }
                    self.offset += 2;
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailer => {
                    let Some(line_end) = find_subsequence(&body[self.offset..], b"\r\n") else {
                        return Ok(None);
                    };
                    self.offset += line_end + 2;
                    if line_end == 0 {
                        return Ok(Some(self.offset));
                    }
                }
            }
        }
    }
}

#[cfg(feature = "io_sync")]
fn dechunk(mut body: &[u8]) -> std::io::Result<Vec<u8>> {
    let err = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunked response");
    let mut out = Vec::new();
    loop {
        let nl = find_subsequence(body, b"\r\n").ok_or_else(err)?;
        let size_line = std::str::from_utf8(&body[..nl]).map_err(|_| err())?;
        // A chunk size may be followed by `;`-separated extensions.
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| err())?;
        body = &body[nl + 2..];
        if size == 0 {
            break;
        }
        let chunk_end = size.checked_add(2).ok_or_else(err)?;
        if body.len() < chunk_end || &body[size..chunk_end] != b"\r\n" {
            return Err(err());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[chunk_end..]; // skip the chunk data and its trailing CRLF
    }
    Ok(out)
}

#[cfg(all(test, feature = "io_sync"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn scoped_link_local_detection() {
        assert!(is_scoped_link_local(&"[fe80::1%3]:80".parse().unwrap()));
        assert!(!is_scoped_link_local(&"[fe80::1]:80".parse().unwrap())); // no zone id
        assert!(!is_scoped_link_local(&"[2001:db8::1%3]:80".parse().unwrap())); // not link-local
        assert!(!is_scoped_link_local(&"192.168.1.1:80".parse().unwrap())); // ipv4
    }

    #[test]
    fn host_without_zone_strips_scope() {
        assert_eq!(
            host_without_zone(&"[fe80::1%3]:1900".parse().unwrap()),
            "[fe80::1]:1900"
        );
        assert_eq!(
            host_without_zone(&"192.168.1.1:1900".parse().unwrap()),
            "192.168.1.1:1900"
        );
    }

    fn serve_once(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(response);
            }
        });
        addr
    }

    #[test]
    fn raw_http_get_content_length() {
        let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        let body = raw_http_request(addr, "GET", "/desc.xml", &[], None, Duration::from_secs(2), 1024 * 1024).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn raw_http_post_chunked() {
        let addr = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let body = raw_http_request(
            addr,
            "POST",
            "/ctl",
            &[("Content-Type", "text/xml")],
            Some("<x/>"),
            Duration::from_secs(2),
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(body, b"hello world");
    }
}
