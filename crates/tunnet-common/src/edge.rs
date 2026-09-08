//! Agent ↔ public-edge reverse-tunnel wire protocol (ALPN `tunnet/edge/1`).
//!
//! After the QUIC connection is up, the agent opens a **control** bi-stream and
//! sends [`EdgeCtrl::Register`]. The edge replies with [`EdgeCtrl::Ok`] or
//! [`EdgeCtrl::Error`]. Subsequent bi-streams opened **by the edge** are raw
//! byte splices to the agent's localhost port (one stream per public connection).

use serde::{Deserialize, Serialize};

pub const EDGE_ALPN: &[u8] = crate::EDGE_ALPN;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EdgeCtrl {
    /// Agent → edge: claim a subdomain on this connection.
    Register {
        tunnel_id: String,
        subdomain: String,
        auth_token: String,
        local_port: u16,
        protocol: String,
    },
    /// Edge → agent: registration accepted.
    Ok,
    /// Edge → agent: registration rejected.
    Error {
        message: String,
    },
    /// Edge → agent on a data bi-stream: connect to `target_port`
    /// (TCP port mappings). Optional `target_ip` is a mesh IPv4; omit = localhost.
    /// HTTPS streams omit this and let the agent peek.
    Forward {
        target_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_ip: Option<String>,
    },
    Ping,
    Pong,
}

impl EdgeCtrl {
    pub fn to_line(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = serde_json::to_vec(self)?;
        buf.push(b'\n');
        Ok(buf)
    }

    pub fn from_line(line: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(line.trim())?)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::EDGE_ALPN as CRATE_EDGE_ALPN;

    fn roundtrip(msg: &EdgeCtrl) -> EdgeCtrl {
        let bytes = msg.to_line().expect("to_line");
        assert!(bytes.ends_with(b"\n"), "to_line must end with newline");
        let line = std::str::from_utf8(&bytes).expect("utf8");
        EdgeCtrl::from_line(line).expect("from_line")
    }

    #[test]
    fn edge_alpn_is_tunnet_edge_1() {
        assert_eq!(CRATE_EDGE_ALPN, b"tunnet/edge/1");
        assert_eq!(EDGE_ALPN, b"tunnet/edge/1");
        assert_eq!(EDGE_ALPN, CRATE_EDGE_ALPN);
    }

    #[test]
    fn register_roundtrip() {
        let msg = EdgeCtrl::Register {
            tunnel_id: "tun_abc".into(),
            subdomain: "demo".into(),
            auth_token: "tok".into(),
            local_port: 3000,
            protocol: "https".into(),
        };
        let bytes = msg.to_line().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains("\"type\":\"register\""));
        assert!(json.contains("\"tunnel_id\":\"tun_abc\""));
        assert!(json.contains("\"local_port\":3000"));
        match roundtrip(&msg) {
            EdgeCtrl::Register {
                tunnel_id,
                subdomain,
                auth_token,
                local_port,
                protocol,
            } => {
                assert_eq!(tunnel_id, "tun_abc");
                assert_eq!(subdomain, "demo");
                assert_eq!(auth_token, "tok");
                assert_eq!(local_port, 3000);
                assert_eq!(protocol, "https");
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    #[test]
    fn ok_roundtrip() {
        let msg = EdgeCtrl::Ok;
        let bytes = msg.to_line().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains("\"type\":\"ok\""));
        assert!(matches!(roundtrip(&msg), EdgeCtrl::Ok));
    }

    #[test]
    fn error_roundtrip() {
        let msg = EdgeCtrl::Error {
            message: "invalid auth token".into(),
        };
        let bytes = msg.to_line().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains("\"type\":\"error\""));
        match roundtrip(&msg) {
            EdgeCtrl::Error { message } => assert_eq!(message, "invalid auth token"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[rstest]
    #[case::without_ip(8080, None)]
    #[case::with_ip(22, Some("10.21.0.2"))]
    fn forward_roundtrip(#[case] port: u16, #[case] ip: Option<&str>) {
        let msg = EdgeCtrl::Forward {
            target_port: port,
            target_ip: ip.map(str::to_string),
        };
        let bytes = msg.to_line().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains("\"type\":\"forward\""));
        assert_eq!(json.contains("target_ip"), ip.is_some());
        match roundtrip(&msg) {
            EdgeCtrl::Forward {
                target_port,
                target_ip,
            } => {
                assert_eq!(target_port, port);
                assert_eq!(target_ip.as_deref(), ip);
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[rstest]
    #[case::ping(EdgeCtrl::Ping, "ping")]
    #[case::pong(EdgeCtrl::Pong, "pong")]
    fn ping_pong_roundtrip(#[case] msg: EdgeCtrl, #[case] tag: &str) {
        let bytes = msg.to_line().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains(&format!("\"type\":\"{tag}\"")));
        let back = roundtrip(&msg);
        assert!(matches!(
            (&back, tag),
            (EdgeCtrl::Ping, "ping") | (EdgeCtrl::Pong, "pong")
        ));
    }

    #[test]
    fn from_line_trims_whitespace() {
        let msg = EdgeCtrl::from_line("  {\"type\":\"ok\"}  \n").expect("parse");
        assert!(matches!(msg, EdgeCtrl::Ok));
    }
}
